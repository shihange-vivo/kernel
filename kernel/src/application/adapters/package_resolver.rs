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

//! Composite package/system dependency resolver (C30, §7.2).
//!
//! [`PackageArtifactResolver`] follows the build-generated manifest exactly:
//! a root or private requester resolves each `DT_NEEDED` through its declared
//! edge — [`DependencySource::PackagePrivate`] opens the manifest's package
//! path as a [`ImageOwnership::SessionPrivate`] image, [`DependencySource::System`]
//! consumes the atomically acquired system batch — and a system requester only
//! sees the system closure. There is no directory search, no `LD_LIBRARY_PATH`,
//! no `RPATH`/`RUNPATH` and no fallback: an undeclared edge aborts the session.

use alloc::vec::Vec;

use blueos_loader::{
    ArtifactIdentity, ArtifactResolver, DependencyName, DependencyRequest, DependencyResolution,
    ErrorContext, ImageOwnership, ImportedImageDescriptor, LoadError, LoadErrorKind, LoadResult,
    PublishedImageDescriptor, ResolvedArtifact,
};

use crate::{
    application::{
        adapters::{
            resolver::{
                identity_from_snapshot, ResolverAuthorities, SystemCandidateClaim,
                SystemCandidatePermit,
            },
            system_paths::{SystemLibraryEntry, SystemLibraryPaths},
            vfs_reader::VfsElfReader,
        },
        package::{self, ApplicationPackageManifest, PackageImageEntry},
        registry::{
            AcquireBatchOutcome, AcquireOutcome, LoadPermit, SystemDsoLease, SystemDsoRegistry,
        },
    },
    vfs::{open_path, FileSnapshotId},
};

/// Resolves a whole application package against its manifest and the registry.
pub struct PackageArtifactResolver {
    package: &'static ApplicationPackageManifest,
    catalog: &'static SystemLibraryPaths,
    registry: SystemDsoRegistry,
    domain: blueos_loader::LinkDomainId,
    root_identity: ArtifactIdentity,
    /// Private images this session opened: identity -> its manifest entry.
    opened_private: Vec<(ArtifactIdentity, &'static PackageImageEntry)>,
    /// The unconsumed portion of the atomic system batch.
    batch_loads: Vec<(DependencyName, LoadPermit)>,
    batch_imports: Vec<(DependencyName, SystemDsoLease, PublishedImageDescriptor)>,
    candidates: Vec<SystemCandidateClaim>,
    leases: Vec<SystemDsoLease>,
    /// SONAMEs whose Ready instance already minted its counted lease this
    /// session, so a repeated edge re-imports without a second reference
    /// (§7.2 rule 6).
    imported_sonames: Vec<DependencyName>,
}

impl PackageArtifactResolver {
    /// Build the resolver and atomically acquire the package's declared system
    /// closure (§7.3). Blocking on an in-flight closure happens here, outside
    /// any loader or manager lock.
    pub fn new(
        package: &'static ApplicationPackageManifest,
        catalog: &'static SystemLibraryPaths,
        registry: SystemDsoRegistry,
        root_identity: &ArtifactIdentity,
        domain: blueos_loader::LinkDomainId,
    ) -> LoadResult<Self> {
        let system_names: Vec<DependencyName> = package
            .system_sonames
            .iter()
            .map(|soname| DependencyName::from_bytes(soname))
            .collect::<LoadResult<_>>()?;

        let (batch_loads, batch_imports) = loop {
            match registry.acquire_batch(domain, &system_names) {
                AcquireBatchOutcome::Acquired(batch) => {
                    break (batch.loads, batch.imports);
                }
                AcquireBatchOutcome::Pending(ticket) => ticket.wait(),
            }
        };

        Ok(Self {
            package,
            catalog,
            registry,
            domain,
            root_identity: root_identity.try_clone()?,
            opened_private: Vec::new(),
            batch_loads,
            batch_imports,
            candidates: Vec::new(),
            leases: Vec::new(),
            imported_sonames: Vec::new(),
        })
    }

    /// Hand over the permits and leases acquired across `resolve` calls.
    pub fn finish_resolution(&mut self) -> ResolverAuthorities {
        let permits = core::mem::take(&mut self.candidates)
            .into_iter()
            .map(|claim| SystemCandidatePermit {
                soname: claim.soname,
                permit: claim.permit,
            })
            .collect();
        let mut leases = core::mem::take(&mut self.leases);
        // Unconsumed batch leases (a declared system SONAME no ELF edge used —
        // rejected by the manifest checker, but be safe) still count.
        leases.extend(core::mem::take(&mut self.batch_imports).into_iter().map(
            |(_, lease, _)| lease,
        ));
        ResolverAuthorities { permits, leases }
    }

    /// The manifest entry for the requester of a SessionPrivate request: the
    /// root, or a private image this session already resolved.
    fn requester_entry(
        &self,
        requester: &blueos_loader::DependencyRequester<'_>,
    ) -> Option<&'static PackageImageEntry> {
        if requester.identity() == &self.root_identity {
            return Some(&self.package.root);
        }
        self.opened_private
            .iter()
            .find(|(identity, _)| identity == requester.identity())
            .map(|(_, entry)| *entry)
    }

    /// Open a private image's manifest path and derive its identity from the
    /// same snapshot (§7.2 rule 4).
    fn open_private(
        &self,
        entry: &'static PackageImageEntry,
    ) -> LoadResult<(VfsElfReader, FileSnapshotId)> {
        let file = open_path(entry.path, libc::O_RDONLY, 0).map_err(|_| backend_error())?;
        let reader = VfsElfReader::new(file);
        let snapshot = reader.snapshot_id();
        Ok((reader, snapshot))
    }

    /// Open a system catalog entry's path and derive its identity (§12.2).
    fn open_system(
        &self,
        entry: &'static SystemLibraryEntry,
    ) -> LoadResult<(VfsElfReader, FileSnapshotId)> {
        let file = open_path(entry.path, libc::O_RDONLY, 0).map_err(|_| backend_error())?;
        let reader = VfsElfReader::new(file);
        let snapshot = reader.snapshot_id();
        Ok((reader, snapshot))
    }

    /// Resolve one declared system edge against the atomic batch (§7.2 rule 5).
    fn resolve_system(
        &mut self,
        needed: &DependencyName,
    ) -> LoadResult<DependencyResolution<VfsElfReader>> {
        let entry = self
            .catalog
            .resolve(needed.as_bytes())
            .ok_or_else(|| unresolved(needed))?;

        // Same-SONAME de-duplication within this link: a second edge to an
        // already-claimed candidate re-opens the same trusted path so the
        // loader's identity de-duplication records only the extra edge.
        if let Some(claim) = self.candidates.iter().find(|c| c.soname == *needed) {
            let (reader, snapshot) = self.open_system(entry)?;
            if snapshot != claim.snapshot {
                return Err(source_changed());
            }
            return Ok(DependencyResolution::Load(ResolvedArtifact::new(
                identity_from_snapshot(snapshot, entry.build_id),
                ImageOwnership::SystemCandidate,
                reader,
            )));
        }

        if let Some((_, permit)) =
            take_by_name(&mut self.batch_loads, needed, |(name, _)| name)
        {
            let (reader, snapshot) = self.open_system(entry)?;
            self.candidates.push(SystemCandidateClaim {
                permit,
                soname: needed.clone(),
                snapshot,
            });
            log::info!(
                "DSO_LOAD soname={}",
                core::str::from_utf8(needed.as_bytes()).unwrap_or("<non-utf8>")
            );
            return Ok(DependencyResolution::Load(ResolvedArtifact::new(
                identity_from_snapshot(snapshot, entry.build_id),
                ImageOwnership::SystemCandidate,
                reader,
            )));
        }

        if let Some((_, lease, descriptor)) =
            take_by_name(&mut self.batch_imports, needed, |(name, _, _)| name)
        {
            self.leases.push(lease);
            self.imported_sonames.push(needed.clone());
            log::info!(
                "DSO_REUSE soname={}",
                core::str::from_utf8(needed.as_bytes()).unwrap_or("<non-utf8>")
            );
            return Ok(DependencyResolution::Import(
                ImportedImageDescriptor::new(descriptor),
            ));
        }

        // The batch minted exactly one lease per Ready SONAME, so an edge from
        // a second requester (e.g. root and a private DSO both needing
        // `libc.so.1`) re-imports the Ready instance through the registry fast
        // path (§7.2 rule 5). The closure is fully acquired, so this can only
        // see `Lease`.
        loop {
            // Repeated edge within this session: the counted reference is
            // already minted; just re-export the descriptor (§7.2 rule 6).
            if self.imported_sonames.contains(needed) {
                let descriptor = self
                    .registry
                    .descriptor(self.domain, needed)
                    .ok_or_else(|| unresolved(needed))?;
                return Ok(DependencyResolution::Import(
                    ImportedImageDescriptor::new(descriptor),
                ));
            }
            match self.registry.acquire_or_begin_load(self.domain, needed.clone()) {
                AcquireOutcome::Lease(lease) => {
                    let descriptor = self
                        .registry
                        .descriptor(self.domain, needed)
                        .ok_or_else(|| unresolved(needed))?;
                    self.leases.push(lease);
                    self.imported_sonames.push(needed.clone());
                    log::info!(
                        "DSO_REUSE soname={}",
                        core::str::from_utf8(needed.as_bytes()).unwrap_or("<non-utf8>")
                    );
                    return Ok(DependencyResolution::Import(
                        ImportedImageDescriptor::new(descriptor),
                    ));
                }
                AcquireOutcome::Pending(handle) => handle.wait(),
                // A declared system edge that neither the batch nor the
                // registry carries: the manifest checker rejects this at build
                // time; fail closed here.
                _ => return Err(unresolved(needed)),
            }
        }
    }
}

impl ArtifactResolver for PackageArtifactResolver {
    type Reader = VfsElfReader;

    fn resolve(
        &mut self,
        request: &DependencyRequest<'_>,
    ) -> LoadResult<DependencyResolution<Self::Reader>> {
        let needed = request.needed();
        let requester = request.requester();

        // System requesters only resolve within the declared system closure;
        // they can never see package-private images or symbols (§7.2 rule 2).
        if matches!(
            requester.ownership(),
            ImageOwnership::SystemCandidate | ImageOwnership::ExternalReady
        ) {
            return self.resolve_system(needed);
        }

        // Root or private requester: the exact manifest edge, or fail closed.
        let requester_entry = self
            .requester_entry(&requester)
            .ok_or_else(|| unresolved(needed))?;
        let edge = package::find_edge(requester_entry, needed.as_bytes())
            .ok_or_else(|| undeclared(needed))?;

        match edge.source {
            package::DependencySource::PackagePrivate => {
                let private = package::find_private_image(self.package, needed.as_bytes())
                    .ok_or_else(|| unresolved(needed))?;
                // Identity de-duplication happens in the loader; a repeated
                // edge re-opens the same manifest path (§7.2 rule 6).
                if let Some((identity, _)) = self
                    .opened_private
                    .iter()
                    .find(|(identity, entry)| *entry == private)
                {
                    let (reader, snapshot) = self.open_private(private)?;
                    let fresh = identity_from_snapshot(snapshot, Some(private.build_id));
                    if identity != &fresh {
                        return Err(source_changed());
                    }
                    return Ok(DependencyResolution::Load(ResolvedArtifact::new(
                        fresh,
                        ImageOwnership::SessionPrivate,
                        reader,
                    )));
                }
                let (reader, snapshot) = self.open_private(private)?;
                let identity = identity_from_snapshot(snapshot, Some(private.build_id));
                self.opened_private.push((identity.clone(), private));
                log::info!(
                    "PKG_LOAD soname={} path={}",
                    core::str::from_utf8(needed.as_bytes()).unwrap_or("<non-utf8>"),
                    private.path
                );
                Ok(DependencyResolution::Load(ResolvedArtifact::new(
                    identity,
                    ImageOwnership::SessionPrivate,
                    reader,
                )))
            }
            package::DependencySource::System => self.resolve_system(needed),
        }
    }
}

/// Remove and return the first entry whose name matches.
fn take_by_name<T>(
    items: &mut Vec<T>,
    needed: &DependencyName,
    name_of: impl Fn(&T) -> &DependencyName,
) -> Option<T> {
    let position = items.iter().position(|item| name_of(item) == needed)?;
    Some(items.swap_remove(position))
}

fn backend_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}

fn source_changed() -> LoadError {
    LoadError::new(LoadErrorKind::SourceChanged, ErrorContext::None)
}

fn unresolved(needed: &DependencyName) -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}

/// An undeclared dependency edge: the requester's manifest has no binding for
/// this `DT_NEEDED` (§7.2).
fn undeclared(needed: &DependencyName) -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::Dependency {
        requester: 0, // filled by the session enrichment with the real image id
        needed: needed.as_bytes().into(),
    })
}
