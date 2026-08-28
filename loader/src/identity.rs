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

use goblin::elf::header::{
    ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, EM_AARCH64, EM_ARM, EM_RISCV, ET_DYN, ET_EXEC,
};

use crate::error::{ErrorContext, LimitKind, LoadError, LoadErrorKind, LoadResult};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ElfClass {
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

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ElfData {
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

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ElfType {
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

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ElfMachine {
    Riscv,
    Aarch64,
    Arm,
    Ohter(u16),
}

impl From<ElfMachine> for u64 {
    fn from(value: ElfMachine) -> Self {
        match value {
            ElfMachine::Aarch64 => u64::from(EM_AARCH64),
            ElfMachine::Arm => u64::from(EM_ARM),
            ElfMachine::Riscv => u64::from(EM_RISCV),
            ElfMachine::Ohter(x) => u64::from(x),
        }
    }
}

pub(crate) struct LoadProfile {
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

pub(crate) struct LoadLimits {
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

pub(crate) struct LoadRequest {
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

pub(crate) struct LoadPolicy {
    pub allow_interpreter: bool,
    pub allow_tls: bool,
    pub allow_executable_stack: bool,
    pub allow_unknown_program_headers: bool,
}

impl LoadPolicy {
    #[inline]
    pub const fn new(
        allow_interpreter: bool,
        allow_tls: bool,
        allow_executable_stack: bool,
        allow_unknown_program_headers: bool,
    ) -> Self {
        Self {
            allow_interpreter,
            allow_tls,
            allow_executable_stack,
            allow_unknown_program_headers,
        }
    }
}

pub(crate) const LOADPOLICY: LoadPolicy = LoadPolicy::new(false, false, false, false);
