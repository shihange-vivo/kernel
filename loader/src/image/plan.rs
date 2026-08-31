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
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    identity::{ElfClass, ElfType, LoadRequest},
    image::{allocate::AllocatedImage, inspect::StackKind},
    memory::{AllocationRequest, ImageAllocation, ImageMemory},
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

    fn allocation_request(&self) -> LoadResult<AllocationRequest> {
        if self.request.profile().r#type() != ElfType::Dyn {
            return Err(
                LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
                    .at_stage(LoadStage::Allocate),
            );
        }

        let size = self.image_span;
        let align = self.max_align;
        if size == 0 {
            return Err(LoadError::new(
                LoadErrorKind::IncorrectLayout,
                ErrorContext::TargetRange {
                    start: self.aligned_min_vaddr,
                    len: size,
                    align,
                },
            )
            .at_stage(LoadStage::Allocate));
        }
        if !align.is_power_of_two() {
            return Err(LoadError::new(
                LoadErrorKind::InvalidAlignment,
                ErrorContext::TargetRange {
                    start: self.aligned_min_vaddr,
                    len: size,
                    align,
                },
            )
            .at_stage(LoadStage::Allocate));
        }
        Ok(AllocationRequest::new(size, align))
    }

    pub fn allocate<M>(self, mut memory: M) -> LoadResult<AllocatedImage<R, M>>
    where
        M: ImageMemory,
    {
        let request = self.allocation_request()?;
        memory
            .allocate_image(request)
            .map_err(|error| error.at_stage(LoadStage::Allocate))?;

        let allocation = memory.allocation()?;

        validate_allocation(allocation, &request, self.request.profile().class())?;
        let load_bias = TargetAddress::new(
            allocation
                .base()
                .checked_sub(self.aligned_min_vaddr)
                .map_err(|error| error.at_stage(LoadStage::Allocate))?,
        );
        Ok(AllocatedImage::new(
            self.reader,
            memory,
            self.aligned_min_vaddr,
            self.aligned_max_vaddr,
            self.max_align,
            load_bias,
            self.request,
            self.entry_vaddr,
            self.canonical_entry_vaddr,
            self.load_segments,
            self.dynamic,
            self.relro,
            self.stack,
            self.interpreter,
            self.tls,
        ))
    }
}

fn validate_allocation(
    allocation: &ImageAllocation,
    request: &AllocationRequest,
    class: ElfClass,
) -> LoadResult<()> {
    let base = allocation.base();
    let aligned = base.get() % request.align() == 0;
    let end = base.checked_add(allocation.len());
    let target_width_valid = end.as_ref().is_ok_and(|end| match class {
        ElfClass::Elf32 => end.get() <= u64::from(u32::MAX),
        ElfClass::Elf64 => true,
    });

    if allocation.len() == request.size()
        && allocation.align() == request.align()
        && aligned
        && target_width_valid
    {
        return Ok(());
    }
    Err(LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base,
            len: allocation.len(),
            align: allocation.align(),
        },
    )
    .at_stage(LoadStage::Allocate))
}
