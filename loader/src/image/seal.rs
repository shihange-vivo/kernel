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
    AllocationLease, CacheSyncOutcome, CodeCache, ErrorContext, ImageAllocation, ImageCommitMemory,
    ImageLoadTransaction, ImageProtectionMemory, LimitKind, LoadError, LoadErrorKind, LoadResult,
    LoadStage, MappedState, MemoryPermissions, RangeResult, RelocatedState, RuntimeImageMetadata,
    StagedImage, TargetAddr, TargetLocation, TargetRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionLevel {
    HardwareEnforced,
    LogicalOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionCapabilities {
    granule: u64,
    max_ranges: usize,
}

impl ProtectionCapabilities {
    pub const fn new(granule: u64, max_ranges: usize) -> Self {
        Self {
            granule,
            max_ranges,
        }
    }

    pub const fn granule(self) -> u64 {
        self.granule
    }

    pub const fn max_ranges(self) -> usize {
        self.max_ranges
    }
}

/// Preallocated protection plan entry and result slot.
///
/// A prepared plan initializes `level` conservatively to `LogicalOnly`. The
/// backend updates it in place only after the corresponding protection change
/// succeeds, so sealing adds no allocation failure after side effects begin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionRecord {
    location: TargetLocation,
    requested_range: TargetRange,
    applied_range: TargetRange,
    permissions: MemoryPermissions,
    level: ProtectionLevel,
}

impl ProtectionRecord {
    pub const fn location(&self) -> TargetLocation {
        self.location
    }

    pub const fn requested_range(&self) -> TargetRange {
        self.requested_range
    }

    pub const fn applied_range(&self) -> TargetRange {
        self.applied_range
    }

    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }

    pub const fn level(&self) -> ProtectionLevel {
        self.level
    }

    fn record_level(&mut self, level: ProtectionLevel) {
        self.level = level;
    }
}

/// Opaque, fixed-length view used while applying a prepared protection plan.
///
/// The backend can inspect every request and record its enforcement level, but
/// cannot replace, remove, duplicate or extend the core-owned result records.
pub struct ProtectionBatch<'a> {
    records: &'a mut [ProtectionRecord],
}

impl<'a> ProtectionBatch<'a> {
    pub(crate) const fn new(records: &'a mut [ProtectionRecord]) -> Self {
        Self { records }
    }

    pub const fn records(&self) -> &[ProtectionRecord] {
        self.records
    }

    /// Record the result for one request, returning false for an invalid index.
    pub fn record_level(&mut self, index: usize, level: ProtectionLevel) -> bool {
        let Some(record) = self.records.get_mut(index) else {
            return false;
        };
        record.record_level(level);
        true
    }
}

#[derive(Debug)]
pub struct AppliedProtectionSet {
    ranges: Vec<ProtectionRecord>,
}

impl AppliedProtectionSet {
    /// Seal the core-owned result slots after a backend completed the batch.
    pub(crate) const fn new(ranges: Vec<ProtectionRecord>) -> Self {
        Self { ranges }
    }

    pub fn ranges(&self) -> &[ProtectionRecord] {
        &self.ranges
    }

    pub fn level(&self) -> ProtectionLevel {
        if self
            .ranges
            .iter()
            .all(|range| range.level == ProtectionLevel::HardwareEnforced)
        {
            ProtectionLevel::HardwareEnforced
        } else {
            ProtectionLevel::LogicalOnly
        }
    }
}

#[derive(Debug)]
pub struct PreparedProtectionPlan {
    ranges: Vec<ProtectionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealRange {
    location: TargetLocation,
    runtime_range: TargetRange,
    permissions: MemoryPermissions,
}

impl SealRange {
    pub const fn location(&self) -> TargetLocation {
        self.location
    }

    pub const fn runtime_range(&self) -> TargetRange {
        self.runtime_range
    }

    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}

#[derive(Debug)]
pub struct SealPlan {
    ranges: Vec<SealRange>,
}

impl SealPlan {
    pub fn ranges(&self) -> &[SealRange] {
        &self.ranges
    }

    fn build(mapped: &MappedState) -> LoadResult<Self> {
        // Every loaded region can be split into three pieces by RELRO and can
        // have an inaccessible allocation gap before it.  One final range is
        // needed for alignment padding after the last region.
        let capacity = mapped
            .regions()
            .len()
            .checked_mul(4)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(seal_oom)?;
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(capacity).map_err(|_| seal_oom())?;

        let mut allocation_cursor = 0;
        for region in mapped.regions() {
            let region_offset = region
                .runtime_range()
                .start()
                .checked_sub(mapped.allocation().target_base());
            let region_offset = at_seal(region_offset)?;
            append_allocation_range(
                mapped,
                &mut ranges,
                allocation_cursor,
                region_offset
                    .checked_sub(allocation_cursor)
                    .ok_or_else(|| {
                        LoadError::new(
                            LoadStage::Seal,
                            LoadErrorKind::OutOfBounds,
                            ErrorContext::TargetRange {
                                start: region.runtime_range().start(),
                                len: region.runtime_range().len(),
                            },
                        )
                    })?,
                MemoryPermissions::NONE,
            )?;

            let source = region.vaddr_range();
            if let Some(relro) = mapped.relro().filter(|relro| relro.overlaps(source)) {
                let source_end = at_seal(source.end())?;
                let relro_end = at_seal(relro.end())?;
                let overlap_start = core::cmp::max(source.start(), relro.start());
                let overlap_end = core::cmp::min(source_end, relro_end);
                append_range(
                    mapped,
                    &mut ranges,
                    source.start(),
                    at_seal(overlap_start.checked_sub(source.start()))?,
                    region.logical_permissions(),
                )?;
                append_range(
                    mapped,
                    &mut ranges,
                    overlap_start,
                    at_seal(overlap_end.checked_sub(overlap_start))?,
                    region
                        .logical_permissions()
                        .without(MemoryPermissions::WRITE),
                )?;
                append_range(
                    mapped,
                    &mut ranges,
                    overlap_end,
                    at_seal(source_end.checked_sub(overlap_end))?,
                    region.logical_permissions(),
                )?;
            } else {
                append_range(
                    mapped,
                    &mut ranges,
                    source.start(),
                    source.len(),
                    region.logical_permissions(),
                )?;
            }
            allocation_cursor = region
                .runtime_range()
                .end()
                .and_then(|end| end.checked_sub(mapped.allocation().target_base()))
                .map_err(|error| error.at(LoadStage::Seal))?;
        }
        append_allocation_range(
            mapped,
            &mut ranges,
            allocation_cursor,
            mapped
                .image_span()
                .checked_sub(allocation_cursor)
                .ok_or_else(|| {
                    LoadError::new(
                        LoadStage::Seal,
                        LoadErrorKind::OutOfBounds,
                        ErrorContext::MemoryAccess {
                            allocation: mapped.allocation().id(),
                            offset: allocation_cursor,
                            len: mapped.image_span(),
                        },
                    )
                })?,
            MemoryPermissions::NONE,
        )?;
        Ok(Self { ranges })
    }
}

impl PreparedProtectionPlan {
    pub(crate) fn prepare<M: ImageProtectionMemory>(
        memory: &M,
        allocation: &ImageAllocation,
        logical: &SealPlan,
    ) -> LoadResult<Self> {
        let prepared = Self::build(allocation, logical, memory.protection_capabilities())?;
        memory
            .validate_protection_aliases(allocation, &prepared)
            .map_err(|error| error.with_stage(LoadStage::Seal))?;
        for range in prepared.ranges() {
            memory
                .validate_access(
                    range.location(),
                    range.applied_range().len(),
                    range.permissions(),
                )
                .map_err(|error| error.at(LoadStage::Seal))?;
        }
        Ok(prepared)
    }

    fn build(
        allocation: &ImageAllocation,
        logical: &SealPlan,
        capabilities: ProtectionCapabilities,
    ) -> LoadResult<Self> {
        let granule = capabilities.granule();
        if !granule.is_power_of_two() {
            return Err(protection_backend_error(allocation));
        }
        if logical.ranges().len() > capabilities.max_ranges() {
            return Err(LoadError::new(
                LoadStage::Seal,
                LoadErrorKind::ResourceLimit,
                ErrorContext::Limit {
                    resource: LimitKind::ProtectionRangeCount,
                    actual: logical.ranges().len() as u64,
                    maximum: capabilities.max_ranges() as u64,
                },
            ));
        }

        let mut ranges: Vec<ProtectionRecord> = Vec::new();
        ranges
            .try_reserve_exact(logical.ranges().len())
            .map_err(|_| seal_oom())?;
        let allocation_end = at_seal(allocation.target_base().checked_add(allocation.len()))?;

        for requested in logical.ranges() {
            let requested_end = at_seal(requested.runtime_range().end())?;
            let applied_start = at_seal(requested.runtime_range().start().align_down(granule))?;
            let applied_end = at_seal(requested_end.align_up(granule))?;
            if applied_start < allocation.target_base() || applied_end > allocation_end {
                return Err(protection_backend_error(allocation));
            }
            let prefix = at_seal(requested.runtime_range().start().checked_sub(applied_start))?;
            let applied_offset = requested
                .location()
                .offset()
                .checked_sub(prefix)
                .ok_or_else(|| protection_backend_error(allocation))?;
            let applied_range = TargetRange::new(
                applied_start,
                at_seal(applied_end.checked_sub(applied_start))?,
            );

            if let Some(previous) = ranges.last() {
                if previous.applied_range.overlaps(applied_range)
                    && previous.permissions != requested.permissions()
                {
                    return Err(LoadError::new(
                        LoadStage::Seal,
                        LoadErrorKind::PermissionConflict,
                        ErrorContext::TargetRange {
                            start: applied_range.start(),
                            len: applied_range.len(),
                        },
                    ));
                }
            }

            ranges.push(ProtectionRecord {
                location: TargetLocation::new(requested.location().allocation(), applied_offset),
                requested_range: requested.runtime_range(),
                applied_range,
                permissions: requested.permissions(),
                level: ProtectionLevel::LogicalOnly,
            });
        }
        Ok(Self { ranges })
    }

    /// Move the preallocated result slots into the core sealing transaction.
    pub(crate) fn into_ranges(self) -> Vec<ProtectionRecord> {
        self.ranges
    }

    pub fn ranges(&self) -> &[ProtectionRecord] {
        &self.ranges
    }
}

#[derive(Debug)]
pub struct SealedState {
    mapped: MappedState,
    metadata: RuntimeImageMetadata,
    seal_plan: SealPlan,
    protections: AppliedProtectionSet,
    cache_sync: CacheSyncOutcome,
}

pub type PreparedImage<'a, M> = StagedImage<'a, M, SealedState>;

#[must_use = "a ready image commit still owns rollback authority"]
pub struct ReadyImageCommit<'a, M: ImageCommitMemory> {
    transaction: ImageLoadTransaction<'a, M>,
    sealed: SealedState,
    install: M::PreparedInstall,
}

impl<'a, M: ImageCommitMemory> StagedImage<'a, M, SealedState> {
    pub fn prepare_commit(self) -> LoadResult<ReadyImageCommit<'a, M>> {
        let (mut transaction, sealed) = self.into_parts();
        let allocation = *transaction.allocation();
        let install = transaction
            .memory()
            .prepare_install(&allocation, &sealed)
            .map_err(|error| error.with_stage(LoadStage::Publish))?;
        Ok(ReadyImageCommit {
            transaction,
            sealed,
            install,
        })
    }
}

impl<M: ImageCommitMemory> ReadyImageCommit<'_, M> {
    pub fn commit(mut self) -> M::CommitReceipt {
        let lease = self.transaction.take_lease();
        // SAFETY: the ready state can only be built by `prepare_commit`, which
        // obtains all three values from this same staged transaction. Its
        // private fields prevent callers from substituting another backend's
        // prepared state, sealed image, or lease.
        unsafe {
            self.transaction
                .memory()
                .commit_install(self.install, self.sealed, lease)
        }
    }
}

impl<'a, M: ImageProtectionMemory> StagedImage<'a, M, RelocatedState> {
    pub fn seal<C>(self, cache: &mut C) -> LoadResult<PreparedImage<'a, M>>
    where
        C: CodeCache,
    {
        let (mut transaction, relocated) = self.into_parts();
        let sealed = relocated.seal(&mut transaction, cache)?;
        Ok(StagedImage::new(transaction, sealed))
    }
}

impl SealedState {
    pub const fn allocation(&self) -> &ImageAllocation {
        self.mapped.allocation()
    }

    pub const fn entry(&self) -> TargetAddr {
        self.mapped.entry()
    }

    pub const fn canonical_entry(&self) -> TargetAddr {
        self.mapped.canonical_entry()
    }

    pub const fn entry_instruction_span(&self) -> u64 {
        self.mapped
            .request()
            .profile()
            .entry_mode()
            .minimum_instruction_size()
    }

    pub const fn load_bias(&self) -> TargetAddr {
        self.mapped.load_bias()
    }

    pub fn protection(&self) -> ProtectionLevel {
        self.protections.level()
    }

    pub const fn protections(&self) -> &AppliedProtectionSet {
        &self.protections
    }

    pub const fn cache_sync(&self) -> &CacheSyncOutcome {
        &self.cache_sync
    }

    pub const fn seal_plan(&self) -> &SealPlan {
        &self.seal_plan
    }

    pub const fn metadata(&self) -> &RuntimeImageMetadata {
        &self.metadata
    }
}

impl RelocatedState {
    pub(crate) fn seal<M, C>(
        self,
        transaction: &mut ImageLoadTransaction<'_, M>,
        cache: &mut C,
    ) -> LoadResult<SealedState>
    where
        M: ImageProtectionMemory,
        C: CodeCache,
    {
        let (mapped, metadata) = self.into_parts();
        let seal_plan = SealPlan::build(&mapped)?;

        let prepared_protection = PreparedProtectionPlan::prepare(
            transaction.memory_ref(),
            mapped.allocation(),
            &seal_plan,
        )?;
        let mut executable_ranges = Vec::new();
        for range in seal_plan.ranges() {
            if range.permissions().contains(MemoryPermissions::EXECUTE) {
                executable_ranges.try_reserve(1).map_err(|_| seal_oom())?;
                executable_ranges.push(range.runtime_range());
            }
        }
        let cache_requirements = cache.requirements();
        let prepared_cache = cache
            .prepare(&executable_ranges)
            .map_err(|error| error.with_stage(LoadStage::Cache))?;
        cache_requirements.validate_prepared(&executable_ranges, &prepared_cache)?;
        let prepared_scope = prepared_cache.scope();
        let prepared_maintenance = prepared_cache.maintenance();
        let cache_sync = cache
            .synchronize(prepared_cache)
            .map_err(|error| error.with_stage(LoadStage::Cache))?;
        cache_sync.validate_completion(&executable_ranges, prepared_scope, prepared_maintenance)?;

        if !seal_plan.ranges().is_empty() {
            transaction.mark_protection_modified();
        }
        let mut protection_records = prepared_protection.into_ranges();
        transaction
            .memory()
            .apply_protection(ProtectionBatch::new(&mut protection_records))
            .map_err(|error| error.with_stage(LoadStage::Seal))?;
        let protections = AppliedProtectionSet::new(protection_records);

        Ok(SealedState {
            mapped,
            metadata,
            seal_plan,
            protections,
            cache_sync,
        })
    }
}

fn append_range(
    mapped: &MappedState,
    ranges: &mut Vec<SealRange>,
    vaddr: TargetAddr,
    len: u64,
    permissions: MemoryPermissions,
) -> LoadResult<()> {
    if len == 0 {
        return Ok(());
    }
    let location = mapped.locate_vaddr_at(LoadStage::Seal, vaddr, len, MemoryPermissions::NONE)?;
    let runtime_range =
        TargetRange::new(at_seal(mapped.load_bias().checked_add(vaddr.get()))?, len);
    at_seal(runtime_range.end())?;

    append_seal_range(ranges, location, runtime_range, permissions)
}

fn append_allocation_range(
    mapped: &MappedState,
    ranges: &mut Vec<SealRange>,
    offset: u64,
    len: u64,
    permissions: MemoryPermissions,
) -> LoadResult<()> {
    if len == 0 {
        return Ok(());
    }
    let location = TargetLocation::new(mapped.allocation().id(), offset);
    let runtime_range = TargetRange::new(
        at_seal(mapped.allocation().target_base().checked_add(offset))?,
        len,
    );
    at_seal(runtime_range.end())?;
    append_seal_range(ranges, location, runtime_range, permissions)
}

fn append_seal_range(
    ranges: &mut Vec<SealRange>,
    location: TargetLocation,
    runtime_range: TargetRange,
    permissions: MemoryPermissions,
) -> LoadResult<()> {
    let len = runtime_range.len();

    if let Some(previous) = ranges.last_mut() {
        let previous_location_end = previous
            .location
            .offset()
            .checked_add(previous.runtime_range.len());
        let previous_runtime_end = at_seal(previous.runtime_range.end())?;
        if previous.permissions == permissions
            && previous.location.allocation() == location.allocation()
            && previous_location_end == Some(location.offset())
            && previous_runtime_end == runtime_range.start()
        {
            let merged_len = previous
                .runtime_range
                .len()
                .checked_add(len)
                .ok_or_else(seal_oom)?;
            previous.runtime_range = TargetRange::new(previous.runtime_range.start(), merged_len);
            return Ok(());
        }
    }

    ranges.push(SealRange {
        location,
        runtime_range,
        permissions,
    });
    Ok(())
}

fn seal_oom() -> LoadError {
    LoadError::new(
        LoadStage::Seal,
        LoadErrorKind::OutOfMemory,
        ErrorContext::None,
    )
}

fn at_seal<T>(result: RangeResult<T>) -> LoadResult<T> {
    result.map_err(|error| error.at(LoadStage::Seal))
}

fn protection_backend_error(allocation: &ImageAllocation) -> LoadError {
    LoadError::new(
        LoadStage::Seal,
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base: allocation.target_base(),
            len: allocation.len(),
            align: allocation.align(),
        },
    )
}
