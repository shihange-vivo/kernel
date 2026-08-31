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
pub(crate) enum Placement {
    Anywhere,
    Fixed(TargetAddress),
}

pub(crate) struct AllocationRequest {
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

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct AllocationId(u32);

impl AllocationId {
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AllocationOwnership {
    Owned,
    BorrowedFixed,
}

#[derive(Debug)]
pub(crate) struct AllocationImageMemory {
    id: AllocationId,
    target_base: TargetAddress,
    len: u64,
    align: u64,
    ownership: AllocationOwnership,
}

impl AllocationImageMemory {
    #[inline]
    pub const fn new(
        id: AllocationId,
        target_base: TargetAddress,
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

    #[inline]
    pub const fn id(&self) -> AllocationId {
        self.id
    }

    #[inline]
    pub const fn target_base(&self) -> TargetAddress {
        self.target_base
    }

    #[inline]
    pub const fn len(&self) -> u64 {
        self.len
    }

    #[inline]
    pub const fn align(&self) -> u64 {
        self.align
    }

    #[inline]
    pub const fn ownership(&self) -> AllocationOwnership {
        self.ownership
    }
}

pub(crate) struct AllocationLocation {
    id: AllocationId,
    offset: u64,
}

impl AllocationLocation {
    #[inline]
    pub const fn new(id: AllocationId, offset: u64) -> Self {
        Self { id, offset }
    }

    #[inline]
    pub const fn id(&self) -> AllocationId {
        self.id
    }

    #[inline]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub fn checked_add(self, value: u64) -> LoadResult<Self> {
        let offset = self.offset.checked_add(value).ok_or_else(|| {
            LoadError::new(
                LoadErrorKind::IntegerOverflow,
                ErrorContext::MemoryAccess {
                    id: self.id,
                    offset: self.offset,
                    len: value,
                },
            )
        })?;
        Ok(Self::new(self.id, offset))
    }
}

pub trait ImageMemory {
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<AllocationImageMemory>;

    fn write(&mut self, location: AllocationLocation, data: &[u8]) -> LoadResult<()>;

    fn zero(&mut self, location: AllocationLocation, len: u64) -> LoadResult<()>;

    fn read(&self, location: AllocationLocation, dst: &mut [u8]) -> LoadResult<()>;
}
