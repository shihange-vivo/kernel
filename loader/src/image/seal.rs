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
    CodeCache, ErrorContext, ImageAllocation, ImageLoadTransaction, ImageMemory, LoadError,
    LoadErrorKind, LoadResult, LoadStage, MappedImage, MemoryPermissions, RelocatedImage,
    RuntimeImageMetadata, TargetAddr, TargetLocation, TargetRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionLevel {
    Hardware,
    LogicalOnly,
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
    ranges: Box<[SealRange]>,
}

impl SealPlan {
    pub fn ranges(&self) -> &[SealRange] {
        &self.ranges
    }

    fn build(mapped: &MappedImage) -> LoadResult<Self> {
        let capacity = mapped.regions().len().checked_mul(3).ok_or_else(seal_oom)?;
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(capacity).map_err(|_| seal_oom())?;

        for region in mapped.regions() {
            let source = region.vaddr_range();
            if let Some(relro) = mapped.relro().filter(|relro| relro.overlaps(source)) {
                let source_end = source.end()?;
                let relro_end = relro.end()?;
                let overlap_start = core::cmp::max(source.start(), relro.start());
                let overlap_end = core::cmp::min(source_end, relro_end);
                append_range(
                    mapped,
                    &mut ranges,
                    source.start(),
                    overlap_start.checked_sub(source.start())?,
                    region.logical_permissions(),
                )?;
                append_range(
                    mapped,
                    &mut ranges,
                    overlap_start,
                    overlap_end.checked_sub(overlap_start)?,
                    region
                        .logical_permissions()
                        .without(MemoryPermissions::WRITE),
                )?;
                append_range(
                    mapped,
                    &mut ranges,
                    overlap_end,
                    source_end.checked_sub(overlap_end)?,
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
        }
        Ok(Self {
            ranges: ranges.into_boxed_slice(),
        })
    }
}

#[derive(Debug)]
pub struct SealedImage {
    mapped: MappedImage,
    metadata: RuntimeImageMetadata,
    seal_plan: SealPlan,
    protection: ProtectionLevel,
}

impl SealedImage {
    pub const fn allocation(&self) -> &ImageAllocation {
        self.mapped.allocation()
    }

    pub const fn entry(&self) -> TargetAddr {
        self.mapped.entry()
    }

    pub const fn canonical_entry(&self) -> TargetAddr {
        self.mapped.canonical_entry()
    }

    pub const fn load_bias(&self) -> TargetAddr {
        self.mapped.load_bias()
    }

    pub const fn protection(&self) -> ProtectionLevel {
        self.protection
    }

    pub const fn seal_plan(&self) -> &SealPlan {
        &self.seal_plan
    }

    pub const fn metadata(&self) -> &RuntimeImageMetadata {
        &self.metadata
    }
}

impl RelocatedImage {
    pub fn seal<M, C>(
        self,
        transaction: &mut ImageLoadTransaction<'_, M>,
        cache: &mut C,
    ) -> LoadResult<SealedImage>
    where
        M: ImageMemory,
        C: CodeCache,
    {
        let (mapped, metadata) = self.into_parts();
        let seal_plan = SealPlan::build(&mapped)?;

        for range in seal_plan.ranges() {
            transaction.memory().validate_access(
                range.location(),
                range.runtime_range().len(),
                range.permissions(),
            )?;
        }
        for range in seal_plan.ranges() {
            if range.permissions().contains(MemoryPermissions::EXECUTE) {
                cache.synchronize(range.runtime_range())?;
            }
        }

        let mut protection = ProtectionLevel::Hardware;
        for range in seal_plan.ranges() {
            let level = transaction.memory().protect(
                range.location(),
                range.runtime_range().len(),
                range.permissions(),
            )?;
            if level == ProtectionLevel::LogicalOnly {
                protection = ProtectionLevel::LogicalOnly;
            }
        }

        Ok(SealedImage {
            mapped,
            metadata,
            seal_plan,
            protection,
        })
    }
}

fn append_range(
    mapped: &MappedImage,
    ranges: &mut Vec<SealRange>,
    vaddr: TargetAddr,
    len: u64,
    permissions: MemoryPermissions,
) -> LoadResult<()> {
    if len == 0 {
        return Ok(());
    }
    let location = mapped.locate_vaddr(vaddr, len, MemoryPermissions::NONE)?;
    let runtime_range = TargetRange::new(mapped.load_bias().checked_add(vaddr.get())?, len);
    runtime_range.end()?;

    if let Some(previous) = ranges.last_mut() {
        let previous_location_end = previous
            .location
            .offset()
            .checked_add(previous.runtime_range.len());
        let previous_runtime_end = previous.runtime_range.end()?;
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
