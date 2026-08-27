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
    AllocationOwnership, ArtifactRequest, DynamicSegmentInfo, ElfReader, ErrorContext, FileRange,
    ImageAllocation, ImageLoadTransaction, ImageLoader, ImageMemory, LoadError, LoadErrorKind,
    LoadResult, LoadStage, MemoryPermissions, ReservedState, StagedImage, TargetAddr,
    TargetLocation, TargetRange,
};

const COPY_BUFFER_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedRegion {
    vaddr_range: TargetRange,
    runtime_range: TargetRange,
    file_range: FileRange,
    allocation_offset: u64,
    logical_permissions: MemoryPermissions,
}

impl LoadedRegion {
    pub const fn vaddr_range(&self) -> TargetRange {
        self.vaddr_range
    }

    pub const fn runtime_range(&self) -> TargetRange {
        self.runtime_range
    }

    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    pub const fn logical_permissions(&self) -> MemoryPermissions {
        self.logical_permissions
    }

    const fn location(&self, allocation: crate::AllocationId) -> TargetLocation {
        TargetLocation::new(allocation, self.allocation_offset)
    }
}

#[derive(Debug)]
pub struct MappedState {
    request: ArtifactRequest,
    allocation: ImageAllocation,
    image_span: u64,
    load_bias: TargetAddr,
    entry: TargetAddr,
    canonical_entry: TargetAddr,
    regions: Box<[LoadedRegion]>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
}

pub type MappedImage<'a, M> = StagedImage<'a, M, MappedState>;

impl<'a, M, R> StagedImage<'a, M, ReservedState<R>>
where
    M: ImageMemory,
    R: ElfReader,
{
    pub fn copy_and_zero(self) -> LoadResult<MappedImage<'a, M>> {
        let (mut transaction, reserved) = self.into_parts();
        let mapped = ImageLoader::new().copy_and_zero(reserved, &mut transaction)?;
        Ok(StagedImage::new(transaction, mapped))
    }
}

impl MappedState {
    pub const fn request(&self) -> &ArtifactRequest {
        &self.request
    }

    pub const fn allocation(&self) -> &ImageAllocation {
        &self.allocation
    }

    pub const fn image_span(&self) -> u64 {
        self.image_span
    }

    pub const fn load_bias(&self) -> TargetAddr {
        self.load_bias
    }

    pub fn regions(&self) -> &[LoadedRegion] {
        &self.regions
    }

    pub fn locate_vaddr(
        &self,
        vaddr: TargetAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<TargetLocation> {
        self.locate_vaddr_at(LoadStage::Map, vaddr, len, permissions)
    }

    pub(crate) fn locate_vaddr_at(
        &self,
        stage: LoadStage,
        vaddr: TargetAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<TargetLocation> {
        let region = self
            .regions
            .iter()
            .find(|region| {
                region.vaddr_range.contains_span(vaddr, len)
                    && region.logical_permissions.contains(permissions)
            })
            .ok_or_else(|| {
                LoadError::new(
                    stage,
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange { start: vaddr, len },
                )
            })?;
        let offset = vaddr
            .checked_sub(region.vaddr_range.start())
            .map_err(|error| error.at(stage))?;
        region
            .location(self.allocation.id())
            .checked_add(offset)
            .map_err(|error| error.at(stage))
    }

    pub fn runtime_address(
        &self,
        vaddr: TargetAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<TargetAddr> {
        self.locate_vaddr(vaddr, len, permissions)?;
        self.load_bias
            .checked_add(vaddr.get())
            .map_err(|error| error.at(LoadStage::Map))
    }

    pub(crate) const fn entry(&self) -> TargetAddr {
        self.entry
    }

    pub(crate) const fn canonical_entry(&self) -> TargetAddr {
        self.canonical_entry
    }

    pub(crate) const fn dynamic(&self) -> Option<DynamicSegmentInfo> {
        self.dynamic
    }

    pub(crate) const fn relro(&self) -> Option<TargetRange> {
        self.relro
    }
}

impl ImageLoader {
    pub(crate) fn copy_and_zero<R, M>(
        &self,
        reserved: ReservedState<R>,
        transaction: &mut ImageLoadTransaction<'_, M>,
    ) -> LoadResult<MappedState>
    where
        R: ElfReader,
        M: ImageMemory,
    {
        let (artifact, parsed, layout, allocation, load_bias) = reserved.into_parts();
        let mut regions = Vec::new();
        regions
            .try_reserve_exact(layout.segments().len())
            .map_err(|_| {
                LoadError::new(
                    LoadStage::Map,
                    LoadErrorKind::OutOfMemory,
                    ErrorContext::None,
                )
            })?;

        for segment in layout.segments() {
            let allocation_offset = segment
                .vaddr_range()
                .start()
                .checked_sub(layout.aligned_min_vaddr())
                .map_err(|error| error.at(LoadStage::Map))?;
            let runtime_start = load_bias
                .checked_add(segment.vaddr_range().start().get())
                .map_err(|error| error.at(LoadStage::Map))?;
            let runtime_range = TargetRange::new(runtime_start, segment.vaddr_range().len());
            runtime_range
                .end()
                .map_err(|error| error.at(LoadStage::Map))?;
            regions.push(LoadedRegion {
                vaddr_range: segment.vaddr_range(),
                runtime_range,
                file_range: segment.file_range(),
                allocation_offset,
                logical_permissions: segment.permissions(),
            });
        }

        let entry = load_bias
            .checked_add(layout.entry_vaddr().get())
            .map_err(|error| error.at(LoadStage::Map))?;
        let canonical_entry = load_bias
            .checked_add(layout.canonical_entry_vaddr().get())
            .map_err(|error| error.at(LoadStage::Map))?;
        let mapped = MappedState {
            request: *artifact.request(),
            allocation,
            image_span: layout.image_span(),
            load_bias,
            entry,
            canonical_entry,
            regions: regions.into_boxed_slice(),
            dynamic: parsed.dynamic(),
            relro: layout.relro(),
        };

        artifact.ensure_snapshot()?;
        preflight_targets(&mapped, transaction.memory())?;
        transaction.mark_bytes_modified();
        if allocation.ownership() == AllocationOwnership::Owned {
            transaction
                .memory()
                .zero(TargetLocation::new(allocation.id(), 0), mapped.image_span())
                .map_err(|error| error.with_stage(LoadStage::Map))?;
        }

        let mut scratch = [0; COPY_BUFFER_SIZE];
        for region in mapped.regions() {
            let location = region.location(allocation.id());
            copy_file_range(
                artifact.reader(),
                region.file_range(),
                location,
                transaction.memory(),
                &mut scratch,
            )?;
            if allocation.ownership() == AllocationOwnership::BorrowedFixed {
                let bss_len = region
                    .vaddr_range()
                    .len()
                    .checked_sub(region.file_range().len())
                    .ok_or_else(|| {
                        LoadError::new(
                            LoadStage::Map,
                            LoadErrorKind::OutOfBounds,
                            ErrorContext::TargetRange {
                                start: region.vaddr_range().start(),
                                len: region.vaddr_range().len(),
                            },
                        )
                    })?;
                transaction
                    .memory()
                    .zero(
                        location
                            .checked_add(region.file_range().len())
                            .map_err(|error| error.at(LoadStage::Map))?,
                        bss_len,
                    )
                    .map_err(|error| error.with_stage(LoadStage::Map))?;
            }
        }
        artifact.ensure_snapshot()?;

        Ok(mapped)
    }
}

fn preflight_targets<M: ImageMemory>(mapped: &MappedState, memory: &M) -> LoadResult<()> {
    if mapped.allocation.ownership() == AllocationOwnership::Owned {
        return memory
            .validate_access(
                TargetLocation::new(mapped.allocation.id(), 0),
                mapped.image_span(),
                MemoryPermissions::WRITE,
            )
            .map_err(|error| error.with_stage(LoadStage::Map));
    }

    for region in mapped.regions() {
        memory
            .validate_access(
                region.location(mapped.allocation.id()),
                region.vaddr_range().len(),
                MemoryPermissions::WRITE,
            )
            .map_err(|error| error.with_stage(LoadStage::Map))?;
        memory
            .validate_access(
                region.location(mapped.allocation.id()),
                region.vaddr_range().len(),
                region.logical_permissions(),
            )
            .map_err(|error| error.with_stage(LoadStage::Map))?;
    }
    Ok(())
}

fn copy_file_range<R: ElfReader, M: ImageMemory>(
    reader: &R,
    file_range: FileRange,
    target: TargetLocation,
    memory: &mut M,
    scratch: &mut [u8; COPY_BUFFER_SIZE],
) -> LoadResult<()> {
    let mut copied = 0;
    while copied < file_range.len() {
        let remaining = file_range.len() - copied;
        let chunk_len = core::cmp::min(remaining, COPY_BUFFER_SIZE as u64) as usize;
        reader.read_exact_at(
            file_range.offset().checked_add(copied).ok_or_else(|| {
                LoadError::new(
                    LoadStage::Map,
                    LoadErrorKind::IntegerOverflow,
                    ErrorContext::FileRange {
                        offset: file_range.offset(),
                        len: file_range.len(),
                        file_len: 0,
                    },
                )
            })?,
            &mut scratch[..chunk_len],
        )?;
        memory
            .write(
                target
                    .checked_add(copied)
                    .map_err(|error| error.at(LoadStage::Map))?,
                &scratch[..chunk_len],
            )
            .map_err(|error| error.with_stage(LoadStage::Map))?;
        copied += chunk_len as u64;
    }
    Ok(())
}
