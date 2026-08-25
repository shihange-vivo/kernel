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
}

impl LoadLimits {
    pub const DEFAULT: Self = Self::new(64 * 1024 * 1024, 128);

    pub const fn new(max_file_len: u64, max_program_headers: u16) -> Self {
        Self {
            max_file_len,
            max_program_headers,
        }
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
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
