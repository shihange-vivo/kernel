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
    AdmittedArtifact, ElfClass, ErrorContext, ImageLayout, ImageLoader, LoadError, LoadErrorKind,
    LoadResult, LoadStage, ParsedImage, PlannedArtifact, RangeError, RangeResult, TargetAddr,
    TargetRange,
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

/// The unique authority to abort or commit an image allocation.
///
/// `ImageAllocation` is intentionally a copyable address descriptor. This
/// lease is neither `Clone` nor `Copy`, so matching numeric allocation IDs are
/// never sufficient to transfer ownership.
#[derive(Debug)]
#[must_use = "an allocation lease must be committed or aborted exactly once"]
pub struct AllocationLease {
    allocation: ImageAllocation,
}

impl AllocationLease {
    /// Creates the unique lease for a backend allocation.
    ///
    /// # Safety
    ///
    /// `allocation` must describe a newly-created, live allocation owned by
    /// this backend. No other lease may exist for the same allocation, and the
    /// backend must honor exactly one later `abort_image`, `release_committed`
    /// or `commit_install` transfer for this lease.
    pub const unsafe fn from_allocation(allocation: ImageAllocation) -> Self {
        Self { allocation }
    }

    pub const fn allocation(&self) -> &ImageAllocation {
        &self.allocation
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MutationProgress {
    Reserved,
    BytesModified,
    ProtectionModified,
}

pub type MemoryResult<T> = core::result::Result<T, MemoryError>;

/// A reusable memory-backend failure before a pipeline stage has claimed it.
///
/// Memory access helpers are consumed by mapping, metadata decoding,
/// relocation and sealing. Requiring the caller to bind the stage prevents a
/// backend's default label from leaking into an unrelated later phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryError {
    kind: LoadErrorKind,
    context: ErrorContext,
}

impl MemoryError {
    pub const fn new(kind: LoadErrorKind, context: ErrorContext) -> Self {
        Self { kind, context }
    }

    pub const fn at(self, stage: LoadStage) -> LoadError {
        LoadError::new(stage, self.kind, self.context)
    }

    pub const fn kind(&self) -> LoadErrorKind {
        self.kind
    }

    pub const fn context(&self) -> &ErrorContext {
        &self.context
    }
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
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<AllocationLease>;

    /// Abort an unpublished image. Implementations must be allocation-free,
    /// non-panicking and infallible. Borrowed fixed images that may have been
    /// modified must be poisoned instead of pretending that bytes were restored.
    fn abort_image(&mut self, lease: AllocationLease, progress: MutationProgress);

    /// Release a successfully committed image owner. This is distinct from
    /// abort: a committed fixed image is not poisoned merely because its owner
    /// is being torn down. Implementations must be allocation-free,
    /// non-panicking and infallible because owner Drop may invoke it.
    fn release_committed(&mut self, lease: AllocationLease);

    fn validate_access(
        &self,
        location: TargetLocation,
        len: u64,
        permissions: crate::MemoryPermissions,
    ) -> MemoryResult<()>;

    fn write(&mut self, location: TargetLocation, data: &[u8]) -> MemoryResult<()>;

    fn zero(&mut self, location: TargetLocation, len: u64) -> MemoryResult<()>;

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> MemoryResult<()>;

    fn protect(
        &mut self,
        location: TargetLocation,
        len: u64,
        permissions: crate::MemoryPermissions,
    ) -> MemoryResult<crate::ProtectionLevel>;
}

pub trait ImageProtectionMemory: ImageMemory {
    fn protection_capabilities(&self) -> crate::ProtectionCapabilities;

    /// Validate backend-specific aliases before cache or protection effects.
    ///
    /// A backend that will report `HardwareEnforced` must reject any writable
    /// alias that would remain for an executable or read-only applied range.
    /// A backend without hardware enforcement may accept the plan, but every
    /// applied range must then remain explicitly `LogicalOnly`.
    fn validate_protection_aliases(
        &self,
        allocation: &ImageAllocation,
        prepared: &crate::PreparedProtectionPlan,
    ) -> LoadResult<()>;

    /// Apply every request in a core-owned, fixed-length batch.
    ///
    /// Implementations may perform an atomic platform batch instead of using
    /// the default loop, but may only inspect requests and record levels by
    /// index. They must return an error on partial failure and must not retain
    /// references to the batch after returning.
    fn apply_protection(&mut self, mut batch: crate::ProtectionBatch<'_>) -> LoadResult<()> {
        for index in 0..batch.records().len() {
            let record = batch.records()[index];
            let level = self
                .protect(
                    record.location(),
                    record.applied_range().len(),
                    record.permissions(),
                )
                .map_err(|error| error.at(LoadStage::Seal))?;
            let _recorded = batch.record_level(index, level);
        }
        Ok(())
    }
}

pub trait ImageCommitMemory: ImageProtectionMemory {
    type PreparedInstall;
    type CommitReceipt;

    fn prepare_install(
        &mut self,
        allocation: &ImageAllocation,
        sealed: &crate::SealedState,
    ) -> LoadResult<Self::PreparedInstall>;

    /// Install only state that was fully prepared by `prepare_install` and
    /// transfer the unique allocation lease to the committed owner.
    ///
    /// This method must not allocate, validate, panic or fail.
    /// The installed owner must retain the lease for the image lifetime and
    /// pass it to `release_committed` exactly once when that lifetime ends.
    ///
    /// # Safety
    ///
    /// `prepared`, `sealed`, and `lease` must all originate from the same
    /// backend transaction and describe the same allocation. `lease` must not
    /// have been transferred or released previously.
    unsafe fn commit_install(
        &mut self,
        prepared: Self::PreparedInstall,
        sealed: crate::SealedState,
        lease: AllocationLease,
    ) -> Self::CommitReceipt;
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

    pub fn checked_add(self, value: u64) -> RangeResult<Self> {
        let offset = self.offset.checked_add(value).ok_or_else(|| {
            RangeError::new(
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
pub struct ReservedState<R> {
    artifact: AdmittedArtifact<R>,
    parsed: ParsedImage,
    layout: ImageLayout,
    allocation: ImageAllocation,
    load_bias: TargetAddr,
}

impl<R> ReservedState<R> {
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

#[must_use = "dropping an active image transaction aborts its allocation"]
pub(crate) struct ImageLoadTransaction<'a, M: ImageMemory> {
    memory: &'a mut M,
    pending: Option<AllocationLease>,
    progress: MutationProgress,
}

impl<'a, M: ImageMemory> ImageLoadTransaction<'a, M> {
    pub(crate) fn new(memory: &'a mut M) -> Self {
        Self {
            memory,
            pending: None,
            progress: MutationProgress::Reserved,
        }
    }

    fn allocate(&mut self, request: &AllocationRequest) -> LoadResult<ImageAllocation> {
        if self.pending.is_some() {
            return Err(LoadError::new(
                LoadStage::Allocate,
                LoadErrorKind::Backend,
                ErrorContext::None,
            ));
        }
        let lease = self
            .memory
            .allocate_image(request)
            .map_err(|error| error.with_stage(LoadStage::Allocate))?;
        let allocation = *lease.allocation();
        self.pending = Some(lease);
        Ok(allocation)
    }

    pub(crate) fn memory(&mut self) -> &mut M {
        self.memory
    }

    pub(crate) fn memory_ref(&self) -> &M {
        self.memory
    }

    pub(crate) fn allocation(&self) -> &ImageAllocation {
        self.pending
            .as_ref()
            .expect("an active image transaction must own a lease")
            .allocation()
    }

    pub(crate) fn mark_bytes_modified(&mut self) {
        self.progress = core::cmp::max(self.progress, MutationProgress::BytesModified);
    }

    pub(crate) fn mark_protection_modified(&mut self) {
        self.progress = MutationProgress::ProtectionModified;
    }

    pub(crate) fn take_lease(&mut self) -> AllocationLease {
        self.pending
            .take()
            .expect("an active image transaction must own a lease")
    }

    #[cfg(test)]
    pub(crate) fn disarm_for_test(mut self) {
        let _lease = self.take_lease();
    }
}

impl<M: ImageMemory> Drop for ImageLoadTransaction<'_, M> {
    fn drop(&mut self) {
        if let Some(lease) = self.pending.take() {
            self.memory.abort_image(lease, self.progress);
        }
    }
}

/// Binds every post-allocation state to the transaction that owns its lease.
/// Production transitions consume this wrapper, so a state from one backend
/// cannot be paired with a transaction from another backend.
#[must_use = "dropping a staged image aborts its unpublished allocation"]
pub struct StagedImage<'a, M: ImageMemory, S> {
    transaction: ImageLoadTransaction<'a, M>,
    state: S,
}

impl<M: ImageMemory, S: core::fmt::Debug> core::fmt::Debug for StagedImage<'_, M, S> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StagedImage")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<'a, M: ImageMemory, S> StagedImage<'a, M, S> {
    pub(crate) const fn new(transaction: ImageLoadTransaction<'a, M>, state: S) -> Self {
        Self { transaction, state }
    }

    pub(crate) fn into_parts(self) -> (ImageLoadTransaction<'a, M>, S) {
        (self.transaction, self.state)
    }
}

pub type ReservedImage<'a, M, R> = StagedImage<'a, M, ReservedState<R>>;

impl ImageLoader {
    pub(crate) fn reserve<R, M>(
        &self,
        planned: PlannedArtifact<R>,
        transaction: &mut ImageLoadTransaction<'_, M>,
    ) -> LoadResult<ReservedState<R>>
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
        let load_bias = layout
            .load_bias_for(
                allocation.target_base(),
                artifact.request().expected_elf_type(),
            )
            .map_err(|error| error.with_stage(LoadStage::Allocate))?;

        Ok(ReservedState {
            artifact,
            parsed,
            layout,
            allocation,
            load_bias,
        })
    }

    pub fn reserve_staged<'a, R, M>(
        &self,
        planned: PlannedArtifact<R>,
        memory: &'a mut M,
    ) -> LoadResult<ReservedImage<'a, M, R>>
    where
        M: ImageMemory,
    {
        let mut transaction = ImageLoadTransaction::new(memory);
        let reserved = self.reserve(planned, &mut transaction)?;
        Ok(StagedImage::new(transaction, reserved))
    }
}

fn validate_target_width(
    allocation: &ImageAllocation,
    image_span: u64,
    class: ElfClass,
) -> LoadResult<()> {
    let end = allocation
        .target_base()
        .checked_add(image_span)
        .map_err(|error| error.at(LoadStage::Allocate))?;
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
    let valid_length = allocation.len() == request.size();
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
                && allocation.len() == range.len()
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
