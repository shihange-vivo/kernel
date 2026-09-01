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
    address::TargetAddress,
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult},
    MemoryPermissions,
};

#[derive(Clone, Copy)]
pub(crate) struct AllocationRequest {
    size: u64,
    align: u64,
}

impl AllocationRequest {
    #[inline]
    pub const fn new(size: u64, align: u64) -> Self {
        Self { size, align }
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct ImageAllocation {
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
    pub const fn align(&self) -> u64 {
        self.align
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub(crate) struct AllocationOffset(u64);

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
