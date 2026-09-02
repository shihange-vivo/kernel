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

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationId(u64);

impl AllocationId {
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationOwnership {
    Owned,
    BorrowedFixed,
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
    id: AllocationId,
    base: TargetAddress,
    len: u64,
    align: u64,
    ownership: AllocationOwnership,
}

impl ImageAllocation {
    #[inline]
    pub const fn new(base: TargetAddress, len: u64, align: u64) -> Self {
        Self::with_identity(
            AllocationId::new(0),
            base,
            len,
            align,
            AllocationOwnership::Owned,
        )
    }

    #[inline]
    pub const fn with_identity(
        id: AllocationId,
        base: TargetAddress,
        len: u64,
        align: u64,
        ownership: AllocationOwnership,
    ) -> Self {
        Self {
            id,
            base,
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

    #[inline]
    pub const fn ownership(&self) -> AllocationOwnership {
        self.ownership
    }
}

/// The unique authority to abort or commit one image allocation.
///
/// Backends create a lease together with the allocation they record. The
/// loader never clones a lease and transfers it exactly once: either back to
/// the backend on abort, or into the backend's committed owner.
#[must_use = "allocation lease must be transferred or aborted exactly once"]
#[derive(Debug)]
pub struct AllocationLease {
    allocation: ImageAllocation,
}

impl AllocationLease {
    #[inline]
    pub const fn new(allocation: ImageAllocation) -> Self {
        Self { allocation }
    }

    #[inline]
    pub const fn allocation(&self) -> &ImageAllocation {
        &self.allocation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum MutationProgress {
    Reserved,
    BytesModified,
    ProtectionModified,
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
    /// Allocate or borrow exactly the logical range requested by the loader.
    /// Returning `Err` must leave no allocation behind.
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<AllocationLease>;

    /// Abort an uncommitted image. This operation must not allocate, fail or
    /// panic. Modified borrowed-fixed ranges must become poisoned.
    fn abort_image(&mut self, allocation: AllocationLease, progress: MutationProgress);

    /// Release a successfully committed image when its owner ends its
    /// lifetime. Borrowed-fixed contents are not restored or poisoned.
    fn release_committed(&mut self, allocation: AllocationLease);

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

/// Backend side of the local two-phase install protocol.
///
/// `prepare_install` performs every fallible validation and constructs all
/// state needed for publication. `commit_install` may only move that prepared
/// state and the unique lease into the committed owner.
pub trait ImageCommitMemory: ImageProtectionMemory {
    type PreparedInstall;
    type CommitReceipt;

    fn prepare_install(
        &mut self,
        allocation: &ImageAllocation,
        sealed: &crate::SealedState,
    ) -> LoadResult<Self::PreparedInstall>;

    /// # Safety
    ///
    /// `prepared`, `sealed`, and `lease` must come from the same active load
    /// transaction on this backend. Implementations must not allocate,
    /// validate, panic, or otherwise fail.
    unsafe fn commit_install(
        &mut self,
        prepared: Self::PreparedInstall,
        sealed: crate::SealedState,
        lease: AllocationLease,
    ) -> Self::CommitReceipt;
}

#[must_use = "dropping an active image transaction aborts its allocation"]
pub(crate) struct ImageLoadTransaction<M: ImageMemory> {
    memory: M,
    pending: Option<AllocationLease>,
    progress: MutationProgress,
}

impl<M: ImageMemory> ImageLoadTransaction<M> {
    #[inline]
    pub(crate) const fn new(memory: M, lease: AllocationLease) -> Self {
        Self {
            memory,
            pending: Some(lease),
            progress: MutationProgress::Reserved,
        }
    }

    #[inline]
    pub(crate) fn allocation(&self) -> &ImageAllocation {
        self.pending
            .as_ref()
            .expect("active image transaction must own its lease")
            .allocation()
    }

    #[inline]
    pub(crate) const fn memory(&self) -> &M {
        &self.memory
    }

    #[inline]
    pub(crate) fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    #[inline]
    pub(crate) fn mark_bytes_modified(&mut self) {
        self.progress = core::cmp::max(self.progress, MutationProgress::BytesModified);
    }

    #[inline]
    pub(crate) fn mark_protection_modified(&mut self) {
        self.progress = MutationProgress::ProtectionModified;
    }

    #[inline]
    pub(crate) fn take_lease(&mut self) -> AllocationLease {
        self.pending
            .take()
            .expect("ready image transaction must own its lease")
    }
}

impl<M: ImageMemory> Drop for ImageLoadTransaction<M> {
    fn drop(&mut self) {
        if let Some(lease) = self.pending.take() {
            self.memory.abort_image(lease, self.progress);
        }
    }
}

impl<M: ImageMemory + ?Sized> ImageMemory for &mut M {
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<AllocationLease> {
        (**self).allocate_image(request)
    }

    fn abort_image(&mut self, allocation: AllocationLease, progress: MutationProgress) {
        (**self).abort_image(allocation, progress)
    }

    fn release_committed(&mut self, allocation: AllocationLease) {
        (**self).release_committed(allocation)
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
