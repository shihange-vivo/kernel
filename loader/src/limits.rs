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

use crate::{ErrorContext, LimitKind, LoadError, LoadErrorKind, LoadResult, LoadStage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadLimits {
    max_file_len: u64,
    max_program_headers: u16,
    max_load_segments: u16,
    max_image_span: u64,
    max_segment_alignment: u64,
    max_layout_bytes: u64,
    max_dynamic_entries: u32,
    max_relocations: u32,
    max_runtime_metadata_bytes: u64,
    max_relocation_operation_bytes: u64,
}

impl LoadLimits {
    pub const DEFAULT: Self = Self::new(64 * 1024 * 1024, 128);

    pub const fn new(max_file_len: u64, max_program_headers: u16) -> Self {
        Self {
            max_file_len,
            max_program_headers,
            max_load_segments: 32,
            max_image_span: 64 * 1024 * 1024,
            max_segment_alignment: 1024 * 1024 * 1024,
            max_layout_bytes: 1024 * 1024,
            max_dynamic_entries: 1024,
            max_relocations: 1024 * 1024,
            max_runtime_metadata_bytes: 64 * 1024 * 1024,
            max_relocation_operation_bytes: 64 * 1024 * 1024,
        }
    }

    /// Conservative production baseline for current MCU boards. Boards may
    /// tighten these values further when constructing an artifact request.
    pub const fn phase0_mcu() -> Self {
        Self::new(8 * 1024 * 1024, 64)
            .with_image_limits(16, 4 * 1024 * 1024)
            .with_layout_limits(64 * 1024, 16 * 1024)
            .with_runtime_limits(512, 16 * 1024)
            .with_runtime_memory_limits(512 * 1024, 512 * 1024)
    }

    pub const fn with_image_limits(mut self, max_load_segments: u16, max_image_span: u64) -> Self {
        self.max_load_segments = max_load_segments;
        self.max_image_span = max_image_span;
        self
    }

    pub const fn with_layout_limits(
        mut self,
        max_segment_alignment: u64,
        max_layout_bytes: u64,
    ) -> Self {
        self.max_segment_alignment = max_segment_alignment;
        self.max_layout_bytes = max_layout_bytes;
        self
    }

    pub const fn with_runtime_limits(
        mut self,
        max_dynamic_entries: u32,
        max_relocations: u32,
    ) -> Self {
        self.max_dynamic_entries = max_dynamic_entries;
        self.max_relocations = max_relocations;
        self
    }

    pub const fn with_runtime_memory_limits(
        mut self,
        max_runtime_metadata_bytes: u64,
        max_relocation_operation_bytes: u64,
    ) -> Self {
        self.max_runtime_metadata_bytes = max_runtime_metadata_bytes;
        self.max_relocation_operation_bytes = max_relocation_operation_bytes;
        self
    }

    pub(crate) fn check_file_len(&self, actual: u64) -> LoadResult<()> {
        if actual <= self.max_file_len {
            return Ok(());
        }
        Err(LoadError::new(
            LoadStage::Validate,
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::FileLength,
                actual,
                maximum: self.max_file_len,
            },
        ))
    }

    pub(crate) fn check_program_header_count(&self, actual: u16) -> LoadResult<()> {
        if actual <= self.max_program_headers {
            return Ok(());
        }
        Err(LoadError::new(
            LoadStage::Validate,
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::ProgramHeaderCount,
                actual: u64::from(actual),
                maximum: u64::from(self.max_program_headers),
            },
        ))
    }

    pub(crate) fn check_load_segment_count(&self, actual: usize) -> LoadResult<()> {
        if actual <= usize::from(self.max_load_segments) {
            return Ok(());
        }
        Err(LoadError::new(
            LoadStage::Plan,
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::LoadSegmentCount,
                actual: actual as u64,
                maximum: u64::from(self.max_load_segments),
            },
        ))
    }

    pub(crate) fn check_image_span(&self, actual: u64) -> LoadResult<()> {
        if actual <= self.max_image_span {
            return Ok(());
        }
        Err(LoadError::new(
            LoadStage::Plan,
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::ImageSpan,
                actual,
                maximum: self.max_image_span,
            },
        ))
    }

    pub(crate) fn check_segment_alignment(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LoadStage::Plan,
            LimitKind::SegmentAlignment,
            actual,
            self.max_segment_alignment,
        )
    }

    pub(crate) fn check_layout_bytes(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LoadStage::Plan,
            LimitKind::LayoutBytes,
            actual,
            self.max_layout_bytes,
        )
    }

    pub(crate) fn check_dynamic_entry_count(&self, actual: u64) -> LoadResult<()> {
        if actual <= u64::from(self.max_dynamic_entries) {
            return Ok(());
        }
        Err(LoadError::new(
            LoadStage::Metadata,
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::DynamicEntryCount,
                actual,
                maximum: u64::from(self.max_dynamic_entries),
            },
        ))
    }

    pub(crate) fn check_relocation_count(&self, actual: u64) -> LoadResult<()> {
        if actual <= u64::from(self.max_relocations) {
            return Ok(());
        }
        Err(LoadError::new(
            LoadStage::Metadata,
            LoadErrorKind::ResourceLimit,
            ErrorContext::Limit {
                resource: LimitKind::RelocationCount,
                actual,
                maximum: u64::from(self.max_relocations),
            },
        ))
    }

    pub(crate) fn check_runtime_metadata_bytes(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LoadStage::Metadata,
            LimitKind::RuntimeMetadataBytes,
            actual,
            self.max_runtime_metadata_bytes,
        )
    }

    pub(crate) fn check_relocation_operation_bytes(&self, actual: u64) -> LoadResult<()> {
        check_limit(
            LoadStage::Relocate,
            LimitKind::RelocationOperationBytes,
            actual,
            self.max_relocation_operation_bytes,
        )
    }
}

fn check_limit(stage: LoadStage, resource: LimitKind, actual: u64, maximum: u64) -> LoadResult<()> {
    if actual <= maximum {
        return Ok(());
    }
    Err(LoadError::new(
        stage,
        LoadErrorKind::ResourceLimit,
        ErrorContext::Limit {
            resource,
            actual,
            maximum,
        },
    ))
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
