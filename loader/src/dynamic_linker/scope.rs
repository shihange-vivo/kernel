// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Frozen symbol scopes (S6, §9).
//!
//! A [`ScopeSet`] is the immutable product of freezing a closed dependency
//! graph: two ordered lookups (the application scope and the system scope) plus
//! the per-image protected/self-first rules. Once frozen it never changes — no
//! image is added and no order is altered (§9.1). The relocation engine (C16)
//! resolves references against it; the session (C15) owns the per-image
//! [`SymbolTable`]s the lookup reads from and charges each hash probe against
//! `max_symbol_lookups` — that counter is mutable session state, so it lives
//! outside this immutable value.

use alloc::{boxed::Box, vec::Vec};

use crate::{
    address::TargetAddress,
    dynamic_linker::{
        graph::DependencyGraph, ImageId, ImageOwnership, SymbolBinding, SymbolDefinition,
        SymbolEntry, SymbolTable, SymbolType, SymbolVisibility,
    },
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
};

/// Region a resolved symbol's canonical target must live in, derived from its
/// ELF type (§9.2): a function target is validated against an executable
/// region, an object/notype target against a readable region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolRegionKind {
    Executable,
    Readable,
}

impl SymbolRegionKind {
    #[inline]
    pub(crate) const fn for_type(symbol_type: SymbolType) -> Self {
        match symbol_type {
            SymbolType::Func => SymbolRegionKind::Executable,
            SymbolType::Object | SymbolType::NoType => SymbolRegionKind::Readable,
        }
    }
}

/// A symbol resolved against the frozen scopes (§9.2).
///
/// `address` is the runtime address (the Thumb bit of a function is preserved);
/// `canonical` clears that bit so a control-flow target check can be performed
/// against an executable region. The owning [`ImageId`] is carried so a later
/// relocation policy can validate `S` against its provider allocation instead of
/// trusting a bare address.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResolvedSymbol {
    owner: ImageId,
    address: TargetAddress,
    canonical: TargetAddress,
    size: u64,
    binding: SymbolBinding,
    region: SymbolRegionKind,
}

impl ResolvedSymbol {
    #[inline]
    fn from_entry(owner: ImageId, entry: &SymbolEntry) -> Self {
        let region = SymbolRegionKind::for_type(entry.symbol_type());
        let address = entry.value();
        let canonical = match entry.symbol_type() {
            SymbolType::Func => TargetAddress::new(address.get() & !1),
            _ => address,
        };
        Self {
            owner,
            address,
            canonical,
            size: entry.size(),
            binding: entry.binding(),
            region,
        }
    }

    #[inline]
    pub(crate) const fn owner(&self) -> ImageId {
        self.owner
    }

    #[inline]
    pub(crate) const fn address(&self) -> TargetAddress {
        self.address
    }

    #[inline]
    pub(crate) const fn canonical(&self) -> TargetAddress {
        self.canonical
    }

    #[inline]
    pub(crate) const fn size(&self) -> u64 {
        self.size
    }

    #[inline]
    pub(crate) const fn binding(&self) -> SymbolBinding {
        self.binding
    }

    #[inline]
    pub(crate) const fn region(&self) -> SymbolRegionKind {
        self.region
    }
}

/// Per-image frozen export rules (§9.1): the owner, the scope it joins, and the
/// indices of its protected definitions — the self-first set. An owner-local
/// reference to one of these always binds to the owner's own definition, never
/// an earlier entry in the search scope (§9.2 rule 2).
#[derive(Debug)]
pub(crate) struct ScopeImage {
    owner: ImageId,
    ownership: ImageOwnership,
    protected: Box<[u32]>,
}

impl ScopeImage {
    #[inline]
    fn is_protected(&self, index: u32) -> bool {
        self.protected.contains(&index)
    }

    #[inline]
    pub(crate) const fn owner(&self) -> ImageId {
        self.owner
    }

    #[inline]
    pub(crate) const fn ownership(&self) -> ImageOwnership {
        self.ownership
    }
}

/// An ordered list of images searched left-to-right for a definition (§9.1).
#[derive(Debug)]
pub(crate) struct SymbolScope {
    ordered_images: Box<[ImageId]>,
}

impl SymbolScope {
    #[inline]
    pub(crate) fn ordered_images(&self) -> &[ImageId] {
        &self.ordered_images
    }
}

/// The frozen symbol scopes of a link session (§9.1).
///
/// `application` is searched root → session-private → system-candidate, each
/// group in BFS discovery order; `system` holds only the system candidates, so a
/// system image's own relocation can never bind an application-private symbol.
/// `per_image` is indexed by [`ImageId`] and records each image's self-first
/// protected rules.
#[derive(Debug)]
pub(crate) struct ScopeSet {
    application: SymbolScope,
    system: SymbolScope,
    per_image: Box<[ScopeImage]>,
}

impl ScopeSet {
    /// Freeze a closed dependency graph into immutable scopes.
    ///
    /// `symbols` is indexed by [`ImageId`] (one [`SymbolTable`] per admitted
    /// image, supplied by the session). The produced value owns no symbol data:
    /// lookups read the tables through `resolve_*`, so the tables must outlive
    /// the `ScopeSet`.
    pub(crate) fn freeze(graph: &DependencyGraph, symbols: &[&SymbolTable]) -> LoadResult<Self> {
        let nodes = graph.nodes();
        let mut session_private = Vec::new();
        let mut system_candidates = Vec::new();
        for node in nodes {
            match node.ownership() {
                ImageOwnership::SessionPrivate => session_private.push(node.id()),
                ImageOwnership::SystemCandidate => system_candidates.push(node.id()),
            }
        }
        // BFS discovery order is the search order (§8.2/§9.1).
        session_private.sort_by_key(|id| nodes[id.get() as usize].discovery_index());
        system_candidates.sort_by_key(|id| nodes[id.get() as usize].discovery_index());

        let mut application_order = session_private;
        application_order
            .try_reserve(system_candidates.len())
            .map_err(|_| scope_oom())?;
        application_order.extend(system_candidates.iter().copied());

        let mut per_image = Vec::new();
        per_image
            .try_reserve_exact(nodes.len())
            .map_err(|_| scope_oom())?;
        for node in nodes {
            let table = symbols
                .get(node.id().get() as usize)
                .ok_or_else(|| scope_error(LoadErrorKind::BadElf, ErrorContext::None))?;
            let protected = collect_protected(table)?;
            per_image.push(ScopeImage {
                owner: node.id(),
                ownership: node.ownership(),
                protected,
            });
        }

        Ok(Self {
            application: SymbolScope {
                ordered_images: application_order.into_boxed_slice(),
            },
            system: SymbolScope {
                ordered_images: system_candidates.into_boxed_slice(),
            },
            per_image: per_image.into_boxed_slice(),
        })
    }

    /// Resolve a global/weak reference by name for `requester` (§9.2).
    ///
    /// A protected owner-local reference binds to the requester's own
    /// definition first (rule 2); otherwise the frozen scope is walked and the
    /// first strong definition wins, falling back to the first weak when no
    /// strong exists (rules 5–6). Hidden/internal and local definitions are not
    /// exported and are skipped (rule 4). Returns `None` when no definition is
    /// found — the caller decides how to treat an undefined strong versus an
    /// undefined weak (rules 7–8), since that depends on the reference's own
    /// binding in the requester's table.
    pub(crate) fn resolve_name(
        &self,
        symbols: &[&SymbolTable],
        requester: ImageId,
        name: &[u8],
    ) -> Option<ResolvedSymbol> {
        if let Some(table) = symbols.get(requester.get() as usize)
            && let Some(index) = table.lookup(name)
            && self
                .per_image
                .get(requester.get() as usize)
                .is_some_and(|image| image.is_protected(index))
        {
            return table
                .entry(index)
                .map(|entry| ResolvedSymbol::from_entry(requester, entry));
        }

        let mut weak = None;
        for &image in self.scope_for(requester).ordered_images() {
            let Some(table) = symbols.get(image.get() as usize) else {
                continue;
            };
            let Some(index) = table.lookup(name) else {
                continue;
            };
            let Some(entry) = table.entry(index) else {
                continue;
            };
            if !is_exportable(entry) {
                continue;
            }
            match entry.binding() {
                SymbolBinding::Global => return Some(ResolvedSymbol::from_entry(image, entry)),
                SymbolBinding::Weak => {
                    weak.get_or_insert(ResolvedSymbol::from_entry(image, entry));
                }
                SymbolBinding::Local => {}
            }
        }
        weak
    }

    /// Resolve a symbol by index within its owner, used for `STB_LOCAL`
    /// references that never enter the external scope (§9.2 rule 1).
    pub(crate) fn resolve_index(
        &self,
        symbols: &[&SymbolTable],
        owner: ImageId,
        index: u32,
    ) -> Option<ResolvedSymbol> {
        let entry = symbols.get(owner.get() as usize)?.entry(index)?;
        (entry.definition() == SymbolDefinition::Defined)
            .then(|| ResolvedSymbol::from_entry(owner, entry))
    }

    #[inline]
    pub(crate) fn application(&self) -> &SymbolScope {
        &self.application
    }

    #[inline]
    pub(crate) fn system(&self) -> &SymbolScope {
        &self.system
    }

    #[inline]
    pub(crate) fn per_image(&self) -> &[ScopeImage] {
        &self.per_image
    }

    fn scope_for(&self, requester: ImageId) -> &SymbolScope {
        let is_system = self
            .per_image
            .get(requester.get() as usize)
            .is_some_and(|image| image.ownership() == ImageOwnership::SystemCandidate);
        if is_system {
            &self.system
        } else {
            &self.application
        }
    }
}

/// Indices of an image's protected, defined, exportable symbols.
fn collect_protected(table: &SymbolTable) -> LoadResult<Box<[u32]>> {
    let mut protected = Vec::new();
    for (index, entry) in table.entries().iter().enumerate() {
        if entry.definition() == SymbolDefinition::Defined
            && entry.visibility() == SymbolVisibility::Protected
            && matches!(entry.binding(), SymbolBinding::Global | SymbolBinding::Weak)
        {
            protected.try_reserve(1).map_err(|_| scope_oom())?;
            protected.push(index as u32);
        }
    }
    Ok(protected.into_boxed_slice())
}

#[inline]
fn is_exportable(entry: &SymbolEntry) -> bool {
    entry.definition() == SymbolDefinition::Defined
        && matches!(entry.binding(), SymbolBinding::Global | SymbolBinding::Weak)
        && matches!(
            entry.visibility(),
            SymbolVisibility::Default | SymbolVisibility::Protected
        )
}

fn scope_error(kind: LoadErrorKind, context: ErrorContext) -> LoadError {
    LoadError::new(kind, context).at_stage(LoadStage::Scope)
}

fn scope_oom() -> LoadError {
    scope_error(LoadErrorKind::OutOfMemory, ErrorContext::None)
}
