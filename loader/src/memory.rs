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

use crate::{
    address::{TargetAddress, TargetRange},
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult},
    MemoryPermissions,
};

/// Where an image wants its memory to come from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placement {
    /// Any suitably aligned address (ET_DYN images).
    Anywhere,
    /// Exactly this virtual range (ET_EXEC images).
    Fixed(TargetRange),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationRequest {
    placement: Placement,
    size: u64,
    align: u64,
}

impl AllocationRequest {
    #[inline]
    pub const fn new(placement: Placement, size: u64, align: u64) -> Self {
        Self {
            placement,
            size,
            align,
        }
    }

    #[inline]
    pub const fn placement(&self) -> Placement {
        self.placement
    }

    #[inline]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[inline]
    pub const fn align(&self) -> u64 {
        self.align
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ImageAllocation {
    base: TargetAddress,
    len: u64,
    align: u64,
}

impl ImageAllocation {
    #[inline]
    pub const fn new(base: TargetAddress, len: u64, align: u64) -> Self {
        Self { base, len, align }
    }

    #[inline]
    pub const fn base(&self) -> TargetAddress {
        self.base
    }

    #[inline]
    pub const fn len(&self) -> u64 {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub const fn align(&self) -> u64 {
        self.align
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub struct AllocationOffset(u64);

impl AllocationOffset {
    #[inline]
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    #[inline]
    pub const fn value(&self) -> u64 {
        self.0
    }

    pub fn checked_add(self, value: u64) -> LoadResult<Self> {
        let offset = self.0.checked_add(value).ok_or_else(|| {
            LoadError::new(
                LoadErrorKind::IntegerOverflow,
                ErrorContext::MemoryAccess {
                    allocation_base: TargetAddress::new(0),
                    allocation_len: 0,
                    allocation_align: 0,
                    offset: self.0,
                    len: value,
                },
            )
        })?;
        Ok(Self::new(offset))
    }
}

pub trait ImageMemory {
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<()>;

    fn allocation(&self) -> LoadResult<&ImageAllocation>;

    fn image_span(&self, offset: AllocationOffset, len: u64) -> LoadResult<*mut u8>;

    fn write(&mut self, offset: AllocationOffset, data: &[u8]) -> LoadResult<()>;

    fn zero(&mut self, offset: AllocationOffset, len: u64) -> LoadResult<()>;

    fn read(&self, offset: AllocationOffset, dst: &mut [u8]) -> LoadResult<()>;
}

pub trait ImageProtectionMemory: ImageMemory {
    fn protect(
        &mut self,
        offset: AllocationOffset,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<crate::image::ProtectionLevel>;

    fn protection_capabilities(&self) -> crate::image::ProtectionCapabilities;

    fn validate_protection_aliases(
        &self,
        allocation: &ImageAllocation,
        prepared: &crate::image::PreparedProtectionPlan,
    ) -> LoadResult<()>;

    fn apply_protection(&mut self, mut batch: crate::image::ProtectionBatch<'_>) -> LoadResult<()> {
        for index in 0..batch.records().len() {
            let record = batch.records()[index];
            let level = self.protect(
                record.allocation_offset(),
                record.applied_range().len(),
                record.permissions(),
            )?;
            let _ = batch.record_level(index, level);
        }
        Ok(())
    }
}

impl<M: ImageMemory + ?Sized> ImageMemory for &mut M {
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<()> {
        (**self).allocate_image(request)
    }

    fn allocation(&self) -> LoadResult<&ImageAllocation> {
        (**self).allocation()
    }

    fn image_span(&self, offset: AllocationOffset, len: u64) -> LoadResult<*mut u8> {
        (**self).image_span(offset, len)
    }

    fn write(&mut self, offset: AllocationOffset, data: &[u8]) -> LoadResult<()> {
        (**self).write(offset, data)
    }

    fn zero(&mut self, offset: AllocationOffset, len: u64) -> LoadResult<()> {
        (**self).zero(offset, len)
    }

    fn read(&self, offset: AllocationOffset, dst: &mut [u8]) -> LoadResult<()> {
        (**self).read(offset, dst)
    }
}

impl<M: ImageProtectionMemory + ?Sized> ImageProtectionMemory for &mut M {
    fn protect(
        &mut self,
        offset: AllocationOffset,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<crate::image::ProtectionLevel> {
        (**self).protect(offset, len, permissions)
    }

    fn protection_capabilities(&self) -> crate::image::ProtectionCapabilities {
        (**self).protection_capabilities()
    }

    fn validate_protection_aliases(
        &self,
        allocation: &ImageAllocation,
        prepared: &crate::image::PreparedProtectionPlan,
    ) -> LoadResult<()> {
        (**self).validate_protection_aliases(allocation, prepared)
    }

    fn apply_protection(&mut self, batch: crate::image::ProtectionBatch<'_>) -> LoadResult<()> {
        (**self).apply_protection(batch)
    }
}
