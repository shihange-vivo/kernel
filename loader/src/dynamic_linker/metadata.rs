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

//! Typed runtime metadata for one decoded image (S4, §7).
//!
//! [`RuntimeImageMetadata`] is the single value the Phase 0.5 linker keeps
//! about an image after S4: the validated dynamic-table provenance, the owned
//! dependency names, the symbol table, the relocation tables and their decoded
//! records, the lifecycle entry points, and a program-header summary. It is
//! produced once at decode time and carried through the relocation/cache/seal
//! typestate chain until the session consumes it (C14/C15).

use alloc::vec::Vec;

use crate::{
    address::{TargetAddress, TargetRange},
    dynamic_linker::{DependencyName, SymbolTable},
    elf::LoadSegmentInfo,
    image::{LoadedRegion, RelocationRecord, RelocationTableKind, StackKind},
    memory::ImageAllocation,
};

/// One relocation table (`DT_REL` or `DT_RELA`): its vaddr, byte extent and
/// entry geometry. `entry_count` is `byte_len / entry_size`, both already
/// validated against the ELF ABI during S4.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RelocationTableInfo {
    kind: RelocationTableKind,
    address: TargetAddress,
    byte_len: u64,
    entry_size: u64,
    entry_count: u64,
}

impl RelocationTableInfo {
    #[inline]
    pub(crate) const fn new(
        kind: RelocationTableKind,
        address: TargetAddress,
        byte_len: u64,
        entry_size: u64,
        entry_count: u64,
    ) -> Self {
        Self {
            kind,
            address,
            byte_len,
            entry_size,
            entry_count,
        }
    }

    #[inline]
    pub(crate) const fn kind(&self) -> RelocationTableKind {
        self.kind
    }

    #[inline]
    pub(crate) const fn address(&self) -> TargetAddress {
        self.address
    }

    #[inline]
    pub(crate) const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[inline]
    pub(crate) const fn entry_size(&self) -> u64 {
        self.entry_size
    }

    #[inline]
    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// The `DT_REL`/`DT_RELA`/`DT_JMPREL` table descriptors plus their decoded
/// records.
///
/// The records are combined in table order (`REL` before `RELA` before
/// `JMPREL`) and retain their ELF symbol indices; only the relocation
/// semantics that the current phase supports survive decode (`symbol_index == 0`
/// for the relative engine until C14 freezes scopes, then symbol-bound records
/// for the session engine).
pub(crate) struct RelocationTables {
    rel: Option<RelocationTableInfo>,
    rela: Option<RelocationTableInfo>,
    jmp_rel: Option<RelocationTableInfo>,
    records: Vec<RelocationRecord>,
}

impl RelocationTables {
    #[inline]
    pub(crate) fn new(
        rel: Option<RelocationTableInfo>,
        rela: Option<RelocationTableInfo>,
        jmp_rel: Option<RelocationTableInfo>,
        records: Vec<RelocationRecord>,
    ) -> Self {
        Self {
            rel,
            rela,
            jmp_rel,
            records,
        }
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            rel: None,
            rela: None,
            jmp_rel: None,
            records: Vec::new(),
        }
    }

    #[inline]
    pub(crate) const fn rel(&self) -> Option<RelocationTableInfo> {
        self.rel
    }

    #[inline]
    pub(crate) const fn rela(&self) -> Option<RelocationTableInfo> {
        self.rela
    }

    #[inline]
    pub(crate) const fn jmp_rel(&self) -> Option<RelocationTableInfo> {
        self.jmp_rel
    }

    #[inline]
    pub(crate) fn records(&self) -> &[RelocationRecord] {
        &self.records
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
}

/// Provenance of the validated `.dynamic` table (§7.2).
///
/// `vaddr`/`byte_len` locate the table in ELF vaddr space; `entry_size`/`entry_count`
/// are derived from the ELF class and the (already validated) table extent.
/// `flags`/`flags_1` are the masked `DT_FLAGS`/`DT_FLAGS_1` values (0 when absent).
#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeDynamicInfo {
    vaddr: TargetAddress,
    byte_len: u64,
    entry_size: u64,
    entry_count: u64,
    flags: u64,
    flags_1: u64,
}

impl RuntimeDynamicInfo {
    #[inline]
    pub(crate) const fn new(
        vaddr: TargetAddress,
        byte_len: u64,
        entry_size: u64,
        entry_count: u64,
        flags: u64,
        flags_1: u64,
    ) -> Self {
        Self {
            vaddr,
            byte_len,
            entry_size,
            entry_count,
            flags,
            flags_1,
        }
    }

    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            vaddr: TargetAddress::new(0),
            byte_len: 0,
            entry_size: 0,
            entry_count: 0,
            flags: 0,
            flags_1: 0,
        }
    }

    #[inline]
    pub(crate) const fn vaddr(&self) -> TargetAddress {
        self.vaddr
    }

    #[inline]
    pub(crate) const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[inline]
    pub(crate) const fn entry_size(&self) -> u64 {
        self.entry_size
    }

    #[inline]
    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    #[inline]
    pub(crate) const fn flags(&self) -> u64 {
        self.flags
    }

    #[inline]
    pub(crate) const fn flags_1(&self) -> u64 {
        self.flags_1
    }
}

/// Lifecycle entry points and array ranges decoded at S4 (§7.6).
///
/// S4 records only the `DT_INIT`/`DT_FINI` targets and the init/fini array
/// *ranges*; the array contents are not fixed into function addresses until
/// after relocation, because an array entry may itself be rewritten in S7.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ImageLifecycleMetadata {
    init: Option<TargetAddress>,
    fini: Option<TargetAddress>,
    preinit_array: Option<TargetRange>,
    init_array: Option<TargetRange>,
    fini_array: Option<TargetRange>,
}

impl ImageLifecycleMetadata {
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            init: None,
            fini: None,
            preinit_array: None,
            init_array: None,
            fini_array: None,
        }
    }

    #[inline]
    pub(crate) const fn new(
        init: Option<TargetAddress>,
        fini: Option<TargetAddress>,
        preinit_array: Option<TargetRange>,
        init_array: Option<TargetRange>,
        fini_array: Option<TargetRange>,
    ) -> Self {
        Self {
            init,
            fini,
            preinit_array,
            init_array,
            fini_array,
        }
    }

    #[inline]
    pub(crate) const fn init(&self) -> Option<TargetAddress> {
        self.init
    }

    #[inline]
    pub(crate) const fn fini(&self) -> Option<TargetAddress> {
        self.fini
    }

    #[inline]
    pub(crate) const fn preinit_array(&self) -> Option<TargetRange> {
        self.preinit_array
    }

    #[inline]
    pub(crate) const fn init_array(&self) -> Option<TargetRange> {
        self.init_array
    }

    #[inline]
    pub(crate) const fn fini_array(&self) -> Option<TargetRange> {
        self.fini_array
    }
}

/// Runtime program-header summary. Skeleton for now: populated once the link
/// product needs `dl_iterate_phdr`-style runtime introspection (C17-a).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProgramHeaderRuntimeInfo;

/// Aggregated, owned runtime metadata for one decoded image (§7.1).
pub(crate) struct RuntimeImageMetadata {
    dynamic: RuntimeDynamicInfo,
    needed: Vec<DependencyName>,
    soname: Option<DependencyName>,
    symbols: SymbolTable,
    relocations: RelocationTables,
    lifecycle: ImageLifecycleMetadata,
    program_headers: ProgramHeaderRuntimeInfo,
}

impl RuntimeImageMetadata {
    #[inline]
    pub(crate) fn new(
        dynamic: RuntimeDynamicInfo,
        needed: Vec<DependencyName>,
        soname: Option<DependencyName>,
        symbols: SymbolTable,
        relocations: RelocationTables,
        lifecycle: ImageLifecycleMetadata,
        program_headers: ProgramHeaderRuntimeInfo,
    ) -> Self {
        Self {
            dynamic,
            needed,
            soname,
            symbols,
            relocations,
            lifecycle,
            program_headers,
        }
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self::new(
            RuntimeDynamicInfo::empty(),
            Vec::new(),
            None,
            SymbolTable::empty(),
            RelocationTables::empty(),
            ImageLifecycleMetadata::empty(),
            ProgramHeaderRuntimeInfo,
        )
    }

    #[inline]
    pub(crate) const fn dynamic(&self) -> &RuntimeDynamicInfo {
        &self.dynamic
    }

    #[inline]
    pub(crate) fn needed(&self) -> &[DependencyName] {
        &self.needed
    }

    #[inline]
    pub(crate) const fn soname(&self) -> Option<&DependencyName> {
        self.soname.as_ref()
    }

    #[inline]
    pub(crate) fn take_soname(&mut self) -> Option<DependencyName> {
        self.soname.take()
    }

    #[inline]
    pub(crate) const fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    #[inline]
    pub(crate) const fn relocations(&self) -> &RelocationTables {
        &self.relocations
    }

    #[inline]
    pub(crate) const fn lifecycle(&self) -> &ImageLifecycleMetadata {
        &self.lifecycle
    }

    #[inline]
    pub(crate) const fn program_headers(&self) -> &ProgramHeaderRuntimeInfo {
        &self.program_headers
    }

    #[inline]
    pub(crate) fn relocation_count(&self) -> usize {
        self.relocations.len()
    }

    /// Total owned runtime metadata bytes this image keeps: the symbol table,
    /// the dependency names, and the decoded relocation records. Charged
    /// against `max_runtime_metadata_bytes` at the end of S4 (§7.4/§14.2).
    pub(crate) fn metadata_bytes(&self) -> u64 {
        let symbols = self.symbols.metadata_bytes();
        let names = self
            .needed
            .iter()
            .map(|name| name.as_bytes().len() as u64)
            .chain(
                self.soname
                    .as_ref()
                    .map(|name| name.as_bytes().len() as u64),
            )
            .fold(0u64, |acc, len| acc.saturating_add(len));
        let records =
            self.relocations.len() as u64 * core::mem::size_of::<RelocationRecord>() as u64;
        symbols
            .checked_add(names)
            .and_then(|v| v.checked_add(records))
            .unwrap_or(u64::MAX)
    }
}

/// Physical identity of one decoded image's backing allocation.
///
/// The layout-locator skeleton for C15: it names the allocation that every
/// later normalized target for this image references. Full vaddr →
/// `TargetLocation { allocation, offset, runtime }` normalization (which also
/// needs the image's [`LoadedRegion`]s and `load_bias`) lands with the
/// session-wide relocation engine in C16 (`relocate.rs`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ImageLayout {
    allocation: ImageAllocation,
}

impl ImageLayout {
    #[inline]
    pub(crate) const fn new(allocation: ImageAllocation) -> Self {
        Self { allocation }
    }

    #[inline]
    pub(crate) const fn allocation(&self) -> ImageAllocation {
        self.allocation
    }
}

/// Owned runtime state of one decoded image (§7.1): the physical allocation
/// layout, the mapped load regions, the aggregate metadata, the load bias, and
/// the load segments (for relocation permission checks).
///
/// The session keeps one of these per admitted image inside a
/// `SessionImage`; the unique allocation lease lives in the session rollback
/// log, never here.
pub(crate) struct RuntimeImageState {
    layout: ImageLayout,
    regions: Vec<LoadedRegion>,
    load_segments: Vec<LoadSegmentInfo>,
    metadata: RuntimeImageMetadata,
    load_bias: TargetAddress,
    runtime_entry: TargetAddress,
    canonical_runtime_entry: TargetAddress,
    relro: Option<TargetRange>,
    stack: StackKind,
}

impl RuntimeImageState {
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        layout: ImageLayout,
        regions: Vec<LoadedRegion>,
        load_segments: Vec<LoadSegmentInfo>,
        metadata: RuntimeImageMetadata,
        load_bias: TargetAddress,
        runtime_entry: TargetAddress,
        canonical_runtime_entry: TargetAddress,
        relro: Option<TargetRange>,
        stack: StackKind,
    ) -> Self {
        Self {
            layout,
            regions,
            load_segments,
            metadata,
            load_bias,
            runtime_entry,
            canonical_runtime_entry,
            relro,
            stack,
        }
    }

    #[inline]
    pub(crate) const fn layout(&self) -> &ImageLayout {
        &self.layout
    }

    #[inline]
    pub(crate) fn regions(&self) -> &[LoadedRegion] {
        &self.regions
    }

    #[inline]
    pub(crate) fn load_segments(&self) -> &[LoadSegmentInfo] {
        &self.load_segments
    }

    #[inline]
    pub(crate) const fn metadata(&self) -> &RuntimeImageMetadata {
        &self.metadata
    }

    #[inline]
    pub(crate) fn take_soname(&mut self) -> Option<DependencyName> {
        self.metadata.take_soname()
    }

    #[inline]
    pub(crate) const fn load_bias(&self) -> TargetAddress {
        self.load_bias
    }

    /// The mapped runtime entry (Thumb bit set on ARM). S3 has already applied
    /// the load bias, so publication must not add it a second time.
    #[inline]
    pub(crate) const fn runtime_entry(&self) -> TargetAddress {
        self.runtime_entry
    }

    #[inline]
    pub(crate) const fn canonical_runtime_entry(&self) -> TargetAddress {
        self.canonical_runtime_entry
    }

    #[inline]
    pub(crate) const fn relro(&self) -> Option<TargetRange> {
        self.relro
    }

    #[inline]
    pub(crate) const fn stack(&self) -> &StackKind {
        &self.stack
    }
}
