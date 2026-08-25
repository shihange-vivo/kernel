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
    LoadResult, LoadStage, MemoryPermissions, ReservedImage, TargetAddr, TargetLocation,
    TargetRange,
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
pub struct MappedImage {
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

impl MappedImage {
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
        let region = self
            .regions
            .iter()
            .find(|region| {
                region.vaddr_range.contains_span(vaddr, len)
                    && region.logical_permissions.contains(permissions)
            })
            .ok_or_else(|| {
                LoadError::new(
                    LoadStage::Map,
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange { start: vaddr, len },
                )
            })?;
        let offset = vaddr.checked_sub(region.vaddr_range.start())?;
        region.location(self.allocation.id()).checked_add(offset)
    }

    pub fn runtime_address(
        &self,
        vaddr: TargetAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<TargetAddr> {
        self.locate_vaddr(vaddr, len, permissions)?;
        self.load_bias.checked_add(vaddr.get())
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
    pub fn copy_and_zero<R, M>(
        &self,
        reserved: ReservedImage<R>,
        transaction: &mut ImageLoadTransaction<'_, M>,
    ) -> LoadResult<MappedImage>
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
                .checked_sub(layout.aligned_min_vaddr())?;
            let runtime_start = load_bias.checked_add(segment.vaddr_range().start().get())?;
            let runtime_range = TargetRange::new(runtime_start, segment.vaddr_range().len());
            runtime_range.end()?;
            regions.push(LoadedRegion {
                vaddr_range: segment.vaddr_range(),
                runtime_range,
                file_range: segment.file_range(),
                allocation_offset,
                logical_permissions: segment.permissions(),
            });
        }

        let entry = load_bias.checked_add(layout.entry_vaddr().get())?;
        let canonical_entry = load_bias.checked_add(layout.canonical_entry_vaddr().get())?;
        let mapped = MappedImage {
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

        preflight_targets(&mapped, transaction.memory())?;
        if allocation.ownership() == AllocationOwnership::Owned {
            transaction
                .memory()
                .zero(TargetLocation::new(allocation.id(), 0), mapped.image_span())?;
        } else {
            for region in mapped.regions() {
                transaction
                    .memory()
                    .zero(region.location(allocation.id()), region.vaddr_range().len())?;
            }
        }

        let mut scratch = [0; COPY_BUFFER_SIZE];
        for region in mapped.regions() {
            copy_file_range(
                artifact.reader(),
                region.file_range(),
                region.location(allocation.id()),
                transaction.memory(),
                &mut scratch,
            )?;
        }

        Ok(mapped)
    }
}

fn preflight_targets<M: ImageMemory>(mapped: &MappedImage, memory: &M) -> LoadResult<()> {
    if mapped.allocation.ownership() == AllocationOwnership::Owned {
        return memory.validate_access(
            TargetLocation::new(mapped.allocation.id(), 0),
            mapped.image_span(),
            MemoryPermissions::WRITE,
        );
    }

    for region in mapped.regions() {
        memory.validate_access(
            region.location(mapped.allocation.id()),
            region.vaddr_range().len(),
            MemoryPermissions::WRITE,
        )?;
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
        memory.write(target.checked_add(copied)?, &scratch[..chunk_len])?;
        copied += chunk_len as u64;
    }
    Ok(())
}
