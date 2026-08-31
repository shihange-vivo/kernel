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

use alloc::{boxed::Box, vec::Vec};

use crate::{
    address::{FileRange, TargetAddress, TargetRange},
    elf::{DynamicSegmentInfo, LoadSegmentInfo},
    identity::LoadRequest,
    image::inspect::StackKind,
    memory::{AllocationOffset, ImageMemory},
    reader::ElfReader,
};

pub(crate) struct LoadedRegion {
    vaddr_range: TargetRange,
    runtime_range: TargetRange,
    file_range: FileRange,
    allocation_offset: AllocationOffset,
}

impl LoadedRegion {
    #[inline]
    pub const fn new(
        vaddr_range: TargetRange,
        runtime_range: TargetRange,
        file_range: FileRange,
        allocation_offset: AllocationOffset,
    ) -> Self {
        Self {
            vaddr_range,
            runtime_range,
            file_range,
            allocation_offset,
        }
    }

    #[inline]
    pub const fn vaddr_range(&self) -> TargetRange {
        self.vaddr_range
    }

    #[inline]
    pub const fn runtime_range(&self) -> TargetRange {
        self.runtime_range
    }

    #[inline]
    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    #[inline]
    pub const fn allocation_offset(&self) -> AllocationOffset {
        self.allocation_offset
    }
}

pub(crate) struct MappedImage<R: ElfReader, M: ImageMemory> {
    reader: R,
    memory: M,
    load_bias: TargetAddress,
    request: LoadRequest,
    entry_vaddr: TargetAddress,
    canonical_entry_vaddr: TargetAddress,
    load_segments: Box<[LoadSegmentInfo]>,
    regions: Vec<LoadedRegion>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack: StackKind,
    interpreter: Option<FileRange>,
    tls: Option<TargetRange>,
}

impl<R: ElfReader, M: ImageMemory> MappedImage<R, M> {
    #[inline]
    pub fn new(
        reader: R,
        memory: M,
        load_bias: TargetAddress,
        request: LoadRequest,
        entry_vaddr: TargetAddress,
        canonical_entry_vaddr: TargetAddress,
        load_segments: Box<[LoadSegmentInfo]>,
        regions: Vec<LoadedRegion>,
        dynamic: Option<DynamicSegmentInfo>,
        relro: Option<TargetRange>,
        stack: StackKind,
        interpreter: Option<FileRange>,
        tls: Option<TargetRange>,
    ) -> Self {
        Self {
            reader,
            memory,
            load_bias,
            request,
            entry_vaddr,
            canonical_entry_vaddr,
            load_segments,
            regions,
            dynamic,
            relro,
            stack,
            interpreter,
            tls,
        }
    }
}
