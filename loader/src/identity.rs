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

use goblin::elf::{
    dynamic::{
        DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_DEBUG, DT_FINI, DT_FINI_ARRAY,
        DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT, DT_INIT_ARRAY,
        DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_PLTGOT, DT_PLTREL, DT_PLTRELSZ, DT_PREINIT_ARRAY,
        DT_PREINIT_ARRAYSZ, DT_REL, DT_RELA, DT_RELACOUNT, DT_RELAENT, DT_RELASZ, DT_RELCOUNT,
        DT_RELENT, DT_RELSZ, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_STRTAB, DT_SYMBOLIC,
        DT_SYMENT, DT_SYMTAB, DT_TEXTREL, DT_TLSDESC_GOT, DT_TLSDESC_PLT, DT_VERDEF, DT_VERDEFNUM,
        DT_VERNEED, DT_VERNEEDNUM, DT_VERSYM,
    },
    header::{
        ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, EM_AARCH64, EM_ARM, EM_RISCV, ET_DYN,
        ET_EXEC,
    },
};

use crate::{
    elf::{DT_RELR, DT_RELRENT, DT_RELRSZ},
    error::{ErrorContext, LimitKind, LoadError, LoadErrorKind, LoadResult},
    memory_mapper::MemoryPermissions,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl From<ElfClass> for u64 {
    fn from(value: ElfClass) -> Self {
        match value {
            ElfClass::Elf32 => u64::from(ELFCLASS32),
            ElfClass::Elf64 => u64::from(ELFCLASS64),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfData {
    Little,
    Big,
}

impl From<ElfData> for u64 {
    fn from(value: ElfData) -> Self {
        match value {
            ElfData::Little => u64::from(ELFDATA2LSB),
            ElfData::Big => u64::from(ELFDATA2MSB),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfType {
    Dyn,
    Exec,
    Other(u16),
}

impl From<ElfType> for u64 {
    fn from(value: ElfType) -> Self {
        match value {
            ElfType::Dyn => u64::from(ET_DYN),
            ElfType::Exec => u64::from(ET_EXEC),
            ElfType::Other(x) => u64::from(x),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfMachine {
    Riscv,
    Aarch64,
    Arm,
    Other(u16),
}

impl From<ElfMachine> for u64 {
    fn from(value: ElfMachine) -> Self {
        match value {
            ElfMachine::Aarch64 => u64::from(EM_AARCH64),
            ElfMachine::Arm => u64::from(EM_ARM),
            ElfMachine::Riscv => u64::from(EM_RISCV),
            ElfMachine::Other(x) => u64::from(x),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadProfile {
    class: ElfClass,
    endian: ElfData,
    machine: ElfMachine,
    r#type: ElfType,
}

impl LoadProfile {
    #[inline]
    pub const fn new(
        class: ElfClass,
        endian: ElfData,
        machine: ElfMachine,
        r#type: ElfType,
    ) -> Self {
        Self {
            class,
            endian,
            machine,
            r#type,
        }
    }

    #[inline]
    pub const fn class(&self) -> ElfClass {
        self.class
    }

    #[inline]
    pub const fn endian(&self) -> ElfData {
        self.endian
    }

    #[inline]
    pub const fn machine(&self) -> ElfMachine {
        self.machine
    }

    #[inline]
    pub const fn r#type(&self) -> ElfType {
        self.r#type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadLimits {
    max_file_len: u64,
    max_program_headers: u16,
    max_load_segments: u16,
    max_image_span: u64,
    max_segment_alignment: u64,
    max_dynamic_entries: u64,
    max_relocations: u64,
    max_runtime_metadata_bytes: u64,
    max_relocation_operation_bytes: u64,
}

impl LoadLimits {
    pub const DEFAULT: Self = Self::new(
        64 * 1024 * 1024,
        128,
        32,
        64 * 1024 * 1024,
        1024 * 1024 * 1024,
        1024,
        1024 * 1024,
        64 * 1024 * 1024,
        64 * 1024 * 1024,
    );

    #[inline]
    pub const fn new(
        max_file_len: u64,
        max_program_headers: u16,
        max_load_segments: u16,
        max_image_span: u64,
        max_segment_alignment: u64,
        max_dynamic_entries: u64,
        max_relocations: u64,
        max_runtime_metadata_bytes: u64,
        max_relocation_operation_bytes: u64,
    ) -> Self {
        Self {
            max_file_len,
            max_program_headers,
            max_load_segments,
            max_image_span,
            max_segment_alignment,
            max_dynamic_entries,
            max_relocations,
            max_runtime_metadata_bytes,
            max_relocation_operation_bytes,
        }
    }

    pub fn check_file_len(&self, actual: u64) -> LoadResult<()> {
        check_limit(LimitKind::FileLength, actual, self.max_file_len)
    }

    pub fn check_program_header_count(&self, actual: u16) -> LoadResult<()> {
        if actual <= self.max_program_headers {
            return Ok(());
        }
        Err(LoadError::new(
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::ProgramHeaderCount,
                actual: u64::from(actual),
                maximum: u64::from(self.max_program_headers),
            },
        ))
    }

    pub fn check_load_segment_count(&self, actual: usize) -> LoadResult<()> {
        if actual <= usize::from(self.max_load_segments) {
            return Ok(());
        }
        Err(LoadError::new(
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::LoadSegmentCount,
                actual: actual as u64,
                maximum: u64::from(self.max_load_segments),
            },
        ))
    }

    pub fn check_image_span(&self, actual: u64) -> LoadResult<()> {
        check_limit(LimitKind::ImageSpan, actual, self.max_image_span)
    }

    pub fn check_segment_alignment(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LimitKind::SegmentAlignment,
            actual,
            self.max_segment_alignment,
        )
    }

    pub fn check_dynamic_entry_count(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LimitKind::DynamicEntryCount,
            actual,
            self.max_dynamic_entries,
        )
    }

    pub fn check_relocation_count(&self, actual: u64) -> LoadResult<()> {
        check_limit(LimitKind::RelocationCount, actual, self.max_relocations)
    }

    pub fn check_runtime_metadata_bytes(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LimitKind::RuntimeMetadataBytes,
            actual,
            self.max_runtime_metadata_bytes,
        )
    }

    pub fn check_relocation_operation_bytes(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LimitKind::RelocationOperationBytes,
            actual,
            self.max_relocation_operation_bytes,
        )
    }
}

fn check_limit(resource: LimitKind, actual: u64, maximum: u64) -> LoadResult<()> {
    if actual <= maximum {
        return Ok(());
    }
    Err(LoadError::new(
        LoadErrorKind::ResourceLimit,
        ErrorContext::Limit {
            resource,
            actual,
            maximum,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadRequest {
    profile: LoadProfile,
    limits: LoadLimits,
}

impl LoadRequest {
    #[inline]
    pub const fn new(profile: LoadProfile, limits: LoadLimits) -> Self {
        Self { profile, limits }
    }

    #[inline]
    pub const fn profile(&self) -> &LoadProfile {
        &self.profile
    }

    #[inline]
    pub const fn limits(&self) -> &LoadLimits {
        &self.limits
    }
}

/// Loader capabilities enabled for the current implementation phase.
///
/// This policy only controls optional ELF semantics. Structural checks and
/// safety invariants such as bounds, overflow, overlap and W+X are enforced
/// independently and cannot be disabled here. A capability must not be
/// enabled until its metadata also has a real consumer in the load pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoadPolicy {
    allow_interpreter: bool,
    allow_tls: bool,
    allow_executable_stack: bool,
    allow_unknown_program_headers: bool,

    allow_execute_only_segments: bool,
    allow_write_only_segments: bool,
    allow_no_access_segments: bool,

    allow_needed: bool,
    allow_plt_relocations: bool,
    allow_relr: bool,
    allow_lifecycle: bool,
    allow_search_paths: bool,
    allow_symbolic_lookup: bool,
    allow_symbol_versions: bool,
    allow_tls_descriptors: bool,
    allow_unknown_dynamic_tags: bool,
    allowed_dynamic_flags: u64,
    allowed_dynamic_flags_1: u64,
}

impl LoadPolicy {
    #[inline]
    const fn phase0() -> Self {
        Self {
            allow_interpreter: false,
            allow_tls: false,
            allow_executable_stack: false,
            allow_unknown_program_headers: false,

            allow_execute_only_segments: false,
            allow_write_only_segments: false,
            allow_no_access_segments: false,

            allow_needed: false,
            allow_plt_relocations: false,
            allow_relr: false,
            allow_lifecycle: false,
            allow_search_paths: false,
            allow_symbolic_lookup: false,
            allow_symbol_versions: false,
            allow_tls_descriptors: false,
            allow_unknown_dynamic_tags: false,
            allowed_dynamic_flags: DF_BIND_NOW,
            allowed_dynamic_flags_1: DF_1_NOW | DF_1_PIE,
        }
    }

    #[inline]
    pub const fn allows_interpreter(&self) -> bool {
        self.allow_interpreter
    }

    #[inline]
    pub const fn allows_tls(&self) -> bool {
        self.allow_tls
    }

    #[inline]
    pub const fn allows_executable_stack(&self) -> bool {
        self.allow_executable_stack
    }

    #[inline]
    pub const fn allows_unknown_program_headers(&self) -> bool {
        self.allow_unknown_program_headers
    }

    /// Returns whether a non-empty PT_LOAD permission set is supported.
    /// W+X is deliberately absent because it is an unconditional invariant.
    pub fn allows_segment_permissions(&self, permissions: MemoryPermissions) -> bool {
        let read_execute = MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE);
        let read_write = MemoryPermissions::READ.bitor(MemoryPermissions::WRITE);
        if permissions == MemoryPermissions::READ
            || permissions == read_execute
            || permissions == read_write
        {
            return true;
        }
        if permissions == MemoryPermissions::EXECUTE {
            return self.allow_execute_only_segments;
        }
        if permissions == MemoryPermissions::WRITE {
            return self.allow_write_only_segments;
        }
        if permissions == MemoryPermissions::NONE {
            return self.allow_no_access_segments;
        }
        false
    }

    /// Returns whether the current phase understands and permits a dynamic
    /// tag. Known metadata that is harmless without a consumer is accepted;
    /// tags that introduce linking semantics are controlled explicitly.
    pub const fn allows_dynamic_tag(&self, tag: u64, value: u64) -> bool {
        match tag {
            // Relative relocation tables consumed by the Phase 0 loader.
            DT_REL | DT_RELSZ | DT_RELENT | DT_RELA | DT_RELASZ | DT_RELAENT => true,

            // Text relocations violate the loader's W^X contract in every
            // phase, so they are not represented by an enable switch.
            DT_TEXTREL => false,

            DT_RELR | DT_RELRSZ | DT_RELRENT => self.allow_relr,
            DT_NEEDED => self.allow_needed,
            DT_PLTRELSZ | DT_PLTREL | DT_JMPREL => self.allow_plt_relocations,
            DT_INIT | DT_FINI | DT_INIT_ARRAY | DT_FINI_ARRAY | DT_INIT_ARRAYSZ
            | DT_FINI_ARRAYSZ | DT_PREINIT_ARRAY | DT_PREINIT_ARRAYSZ => self.allow_lifecycle,
            DT_RPATH | DT_RUNPATH => self.allow_search_paths,
            DT_SYMBOLIC => self.allow_symbolic_lookup,
            DT_VERSYM | DT_VERDEF | DT_VERDEFNUM | DT_VERNEED | DT_VERNEEDNUM => {
                self.allow_symbol_versions
            }
            DT_TLSDESC_PLT | DT_TLSDESC_GOT => self.allow_tls_descriptors,

            DT_FLAGS => value & !self.allowed_dynamic_flags == 0,
            DT_FLAGS_1 => value & !self.allowed_dynamic_flags_1 == 0,

            // Recognized metadata that does not by itself request an
            // unsupported runtime operation.
            DT_SONAME | DT_PLTGOT | DT_HASH | DT_STRTAB | DT_SYMTAB | DT_STRSZ | DT_SYMENT
            | DT_DEBUG | DT_BIND_NOW | DT_GNU_HASH | DT_RELACOUNT | DT_RELCOUNT => true,
            _ => self.allow_unknown_dynamic_tags,
        }
    }
}

pub(crate) const PHASE0_LOAD_POLICY: LoadPolicy = LoadPolicy::phase0();
