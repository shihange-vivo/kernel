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

use alloc::boxed::Box;

use crate::{
    address::{FileRange, TargetAddress, TargetRange},
    elf::{DynamicSegmentInfo, LoadSegmentInfo},
    identity::LoadRequest,
    image::inspect::StackKind,
    reader::ElfReader,
};

pub(crate) struct PlannedImage<R: ElfReader> {
    reader: R,
    request: LoadRequest,
    aligned_min_vaddr: TargetAddress,
    aligned_max_vaddr: TargetAddress,
    image_span: u64,
    max_align: u64,
    entry_vaddr: TargetAddress,
    canonical_entry_vaddr: TargetAddress,
    load_segments: Box<[LoadSegmentInfo]>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack: StackKind,
    interpreter: Option<FileRange>,
    tls: Option<TargetRange>,
}

impl<R: ElfReader> PlannedImage<R> {
    #[inline]
    pub const fn new(
        reader: R,
        request: LoadRequest,
        aligned_min_vaddr: TargetAddress,
        aligned_max_vaddr: TargetAddress,
        image_span: u64,
        max_align: u64,
        entry_vaddr: TargetAddress,
        canonical_entry_vaddr: TargetAddress,
        load_segments: Box<[LoadSegmentInfo]>,
        dynamic: Option<DynamicSegmentInfo>,
        relro: Option<TargetRange>,
        stack: StackKind,
        interpreter: Option<FileRange>,
        tls: Option<TargetRange>,
    ) -> Self {
        Self {
            reader,
            request,
            aligned_min_vaddr,
            aligned_max_vaddr,
            image_span,
            max_align,
            entry_vaddr,
            canonical_entry_vaddr,
            load_segments,
            dynamic,
            relro,
            stack,
            interpreter,
            tls,
        }
    }
}
