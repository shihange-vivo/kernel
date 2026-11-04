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

//! One image reservation and the loadable byte ranges inside it.

use alloc::vec::Vec;

use super::{AllocationOffset, AllocationRequest, MemoryPermissions, Placement, TargetAddress};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    LoadError, LoadResult,
};

/// A nonempty PT_LOAD memory range, relative to the image reservation base.
///
/// Permissions describe the segment's intended execution state. The backend
/// must still provide loader reads and writes until final protection is applied.
/// File offsets and initialized sizes remain the loader's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentLayout {
    offset: AllocationOffset,
    memory_size: u64,
    permissions: MemoryPermissions,
}

impl SegmentLayout {
    pub const fn new(
        offset: AllocationOffset,
        memory_size: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            offset,
            memory_size,
            permissions,
        }
    }

    pub const fn offset(&self) -> AllocationOffset {
        self.offset
    }

    pub const fn memory_size(&self) -> u64 {
        self.memory_size
    }

    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}

/// Validated layout of one image, independent of its physical backing.
///
/// The complete span is reserved once, so every segment uses the same load
/// bias. Segments are sorted, nonempty, disjoint byte ranges inside that span.
/// Gaps need not have physical backing. A paging backend must prepare shared
/// boundary pages only once and reject unsupported page permission conflicts.
/// This value owns layout metadata only; cloning it does not create another
/// reservation or duplicate the unique allocation lease.
#[derive(Clone, Debug)]
pub struct ImageLayout {
    request: AllocationRequest,
    segments: Vec<SegmentLayout>,
}

impl ImageLayout {
    pub fn new(request: AllocationRequest, segments: Vec<SegmentLayout>) -> LoadResult<Self> {
        let base = match request.placement() {
            Placement::Anywhere => TargetAddress::new(0),
            Placement::Fixed(range) => range.start(),
        };
        let error = |kind| {
            LoadError::new(
                kind,
                ErrorContext::TargetRange {
                    start: base,
                    len: request.size(),
                    align: request.align(),
                },
            )
        };
        if !request.align().is_power_of_two() {
            return Err(error(LoadErrorKind::InvalidAlignment));
        }
        if request.size() == 0 || segments.is_empty() {
            return Err(error(LoadErrorKind::IncorrectLayout));
        }
        if let Placement::Fixed(range) = request.placement() {
            if range.len() != request.size() || !base.get().is_multiple_of(request.align()) {
                return Err(error(LoadErrorKind::IncorrectLayout));
            }
            range.end()?;
        }
        let mut previous_end = 0;
        for segment in &segments {
            let start = segment.offset().value();
            let end = start
                .checked_add(segment.memory_size())
                .ok_or_else(|| error(LoadErrorKind::IntegerOverflow))?;
            if segment.memory_size() == 0 || start < previous_end {
                return Err(error(LoadErrorKind::IncorrectLayout));
            }
            if end > request.size() {
                return Err(error(LoadErrorKind::OutOfBounds));
            }
            previous_end = end;
        }
        Ok(Self { request, segments })
    }

    pub const fn request(&self) -> AllocationRequest {
        self.request
    }

    pub fn segments(&self) -> &[SegmentLayout] {
        &self.segments
    }
}
