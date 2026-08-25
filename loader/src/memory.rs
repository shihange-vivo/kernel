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

use alloc::vec::Vec;

use crate::{
    AdmittedArtifact, ElfClass, ErrorContext, ImageLayout, ImageLoader, LoadError, LoadErrorKind,
    LoadResult, LoadStage, ParsedImage, PlannedArtifact, TargetAddr, TargetRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placement {
    Anywhere,
    Fixed(TargetRange),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationRequest {
    placement: Placement,
    size: u64,
    align: u64,
}

impl AllocationRequest {
    pub const fn new(placement: Placement, size: u64, align: u64) -> Self {
        Self {
            placement,
            size,
            align,
        }
    }

    pub const fn placement(&self) -> Placement {
        self.placement
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn align(&self) -> u64 {
        self.align
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AllocationId(u32);

impl AllocationId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationOwnership {
    Owned,
    BorrowedFixed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageAllocation {
    id: AllocationId,
    target_base: TargetAddr,
    len: u64,
    align: u64,
    ownership: AllocationOwnership,
}

impl ImageAllocation {
    pub const fn new(
        id: AllocationId,
        target_base: TargetAddr,
        len: u64,
        align: u64,
        ownership: AllocationOwnership,
    ) -> Self {
        Self {
            id,
            target_base,
            len,
            align,
            ownership,
        }
    }

    pub const fn id(&self) -> AllocationId {
        self.id
    }

    pub const fn target_base(&self) -> TargetAddr {
        self.target_base
    }

    pub const fn len(&self) -> u64 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn align(&self) -> u64 {
        self.align
    }

    pub const fn ownership(&self) -> AllocationOwnership {
        self.ownership
    }
}

pub trait ImageMemory {
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<ImageAllocation>;

    fn release(&mut self, allocation: AllocationId);

    fn validate_access(
        &self,
        location: TargetLocation,
        len: u64,
        permissions: crate::MemoryPermissions,
    ) -> LoadResult<()>;

    fn write(&mut self, location: TargetLocation, data: &[u8]) -> LoadResult<()>;

    fn zero(&mut self, location: TargetLocation, len: u64) -> LoadResult<()>;

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> LoadResult<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetLocation {
    allocation: AllocationId,
    offset: u64,
}

impl TargetLocation {
    pub const fn new(allocation: AllocationId, offset: u64) -> Self {
        Self { allocation, offset }
    }

    pub const fn allocation(self) -> AllocationId {
        self.allocation
    }

    pub const fn offset(self) -> u64 {
        self.offset
    }

    pub fn checked_add(self, value: u64) -> LoadResult<Self> {
        let offset = self.offset.checked_add(value).ok_or_else(|| {
            LoadError::new(
                LoadStage::Map,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::MemoryAccess {
                    allocation: self.allocation,
                    offset: self.offset,
                    len: value,
                },
            )
        })?;
        Ok(Self::new(self.allocation, offset))
    }
}

#[derive(Debug)]
pub struct ReservedImage<R> {
    artifact: AdmittedArtifact<R>,
    parsed: ParsedImage,
    layout: ImageLayout,
    allocation: ImageAllocation,
    load_bias: TargetAddr,
}

impl<R> ReservedImage<R> {
    pub const fn artifact(&self) -> &AdmittedArtifact<R> {
        &self.artifact
    }

    pub const fn parsed(&self) -> &ParsedImage {
        &self.parsed
    }

    pub const fn layout(&self) -> &ImageLayout {
        &self.layout
    }

    pub const fn allocation(&self) -> &ImageAllocation {
        &self.allocation
    }

    pub const fn load_bias(&self) -> TargetAddr {
        self.load_bias
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AdmittedArtifact<R>,
        ParsedImage,
        ImageLayout,
        ImageAllocation,
        TargetAddr,
    ) {
        (
            self.artifact,
            self.parsed,
            self.layout,
            self.allocation,
            self.load_bias,
        )
    }
}

pub struct ImageLoadTransaction<'a, M: ImageMemory> {
    memory: &'a mut M,
    rollback_allocations: Vec<AllocationId>,
    committed: bool,
}

impl<'a, M: ImageMemory> ImageLoadTransaction<'a, M> {
    pub fn new(memory: &'a mut M) -> Self {
        Self {
            memory,
            rollback_allocations: Vec::new(),
            committed: false,
        }
    }

    fn allocate(&mut self, request: &AllocationRequest) -> LoadResult<ImageAllocation> {
        let allocation = self.memory.allocate_image(request)?;
        if self.rollback_allocations.try_reserve_exact(1).is_err() {
            self.memory.release(allocation.id());
            return Err(LoadError::new(
                LoadStage::Allocate,
                LoadErrorKind::OutOfMemory,
                ErrorContext::None,
            ));
        }
        self.rollback_allocations.push(allocation.id());
        Ok(allocation)
    }

    pub(crate) fn memory(&mut self) -> &mut M {
        self.memory
    }

    #[cfg(test)]
    pub(crate) fn disarm_for_test(mut self) {
        self.committed = true;
    }
}

impl<M: ImageMemory> Drop for ImageLoadTransaction<'_, M> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for allocation in self.rollback_allocations.drain(..).rev() {
            self.memory.release(allocation);
        }
    }
}

impl ImageLoader {
    pub fn reserve<R, M>(
        &self,
        planned: PlannedArtifact<R>,
        transaction: &mut ImageLoadTransaction<'_, M>,
    ) -> LoadResult<ReservedImage<R>>
    where
        M: ImageMemory,
    {
        let (artifact, parsed, layout) = planned.into_parts();
        let request = layout.allocation_request(artifact.request().expected_elf_type());
        let allocation = transaction.allocate(&request)?;
        validate_allocation(&allocation, &request)?;
        validate_target_width(
            &allocation,
            request.size(),
            artifact.request().profile().class(),
        )?;
        let load_bias = layout.load_bias_for(
            allocation.target_base(),
            artifact.request().expected_elf_type(),
        )?;

        Ok(ReservedImage {
            artifact,
            parsed,
            layout,
            allocation,
            load_bias,
        })
    }
}

fn validate_target_width(
    allocation: &ImageAllocation,
    image_span: u64,
    class: ElfClass,
) -> LoadResult<()> {
    let end = allocation.target_base().checked_add(image_span)?;
    let valid = match class {
        ElfClass::Elf32 => end.get() <= u64::from(u32::MAX) + 1,
        ElfClass::Elf64 => true,
    };
    if valid {
        Ok(())
    } else {
        Err(LoadError::new(
            LoadStage::Allocate,
            LoadErrorKind::OutOfBounds,
            ErrorContext::Allocation {
                base: allocation.target_base(),
                len: image_span,
                align: allocation.align(),
            },
        ))
    }
}

fn validate_allocation(
    allocation: &ImageAllocation,
    request: &AllocationRequest,
) -> LoadResult<()> {
    let valid_length = allocation.len() >= request.size();
    let valid_alignment = request.align().is_power_of_two()
        && allocation.align() >= request.align()
        && allocation.align().is_power_of_two()
        && allocation.target_base().get() % allocation.align() == 0;
    let valid_end = allocation.target_base().checked_add(request.size()).is_ok();
    let valid_placement = match request.placement() {
        Placement::Anywhere => allocation.ownership() == AllocationOwnership::Owned,
        Placement::Fixed(range) => {
            allocation.ownership() == AllocationOwnership::BorrowedFixed
                && allocation.target_base() == range.start()
                && allocation.len() >= range.len()
        }
    };
    if valid_length && valid_alignment && valid_end && valid_placement {
        return Ok(());
    }

    Err(LoadError::new(
        LoadStage::Allocate,
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base: allocation.target_base(),
            len: allocation.len(),
            align: allocation.align(),
        },
    ))
}
