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

use super::FileRange;
use crate::memory::{MemoryPermissions, TargetAddress, TargetRange};

#[derive(Debug)]
pub(crate) struct LoadSegmentInfo {
    index: u16,
    file_range: FileRange,
    vaddr: TargetAddress,
    memory_size: u64,
    align: u64,
    permissions: MemoryPermissions,
}

impl LoadSegmentInfo {
    pub(crate) const fn new(
        index: u16,
        file_range: FileRange,
        vaddr: TargetAddress,
        memory_size: u64,
        align: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            index,
            file_range,
            vaddr,
            memory_size,
            align,
            permissions,
        }
    }

    pub(crate) const fn index(&self) -> u16 {
        self.index
    }

    pub(crate) const fn file_range(&self) -> FileRange {
        self.file_range
    }

    pub(crate) const fn vaddr(&self) -> TargetAddress {
        self.vaddr
    }

    pub(crate) const fn memory_size(&self) -> u64 {
        self.memory_size
    }

    pub(crate) const fn align(&self) -> u64 {
        self.align
    }

    pub(crate) const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}

/// Locate an ELF virtual span wholly backed by one load segment's file bytes.
pub(super) fn vaddr_to_file_range(
    segments: &[LoadSegmentInfo],
    address: TargetAddress,
    len: u64,
) -> Option<FileRange> {
    let file = vaddr_file_extent(segments, address)?;
    (len <= file.len()).then_some(FileRange::new(file.offset(), len))
}

/// File-backed bytes from this virtual address to the end of its load segment.
pub(super) fn vaddr_file_extent(
    segments: &[LoadSegmentInfo],
    address: TargetAddress,
) -> Option<FileRange> {
    let segment = segments.iter().find(|segment| {
        TargetRange::new(segment.vaddr, segment.file_range.len()).contains_span(address, 1)
    })?;
    let displacement = address.get().checked_sub(segment.vaddr.get())?;
    let offset = segment.file_range.offset().checked_add(displacement)?;
    Some(FileRange::new(
        offset,
        segment.file_range.len() - displacement,
    ))
}
