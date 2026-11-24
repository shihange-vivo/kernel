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

//! Validate, encode and write relocation values to one mapped image.

use crate::{
    elf::{ElfClass, ElfData, LoadSegmentInfo, RelocationRecord},
    error::{ErrorContext, LoadErrorKind},
    memory::{AllocationOffset, ImageMapping, MemoryPermissions, TargetAddress, TargetRange},
    LoadError, LoadResult,
};
use alloc::vec::Vec;

struct PlannedWrite {
    target: TargetAddress,
    raw_type: u32,
    symbol_index: u32,
    bytes: [u8; 8],
}

impl PlannedWrite {
    fn context(&self) -> ErrorContext {
        ErrorContext::Relocation {
            target: self.target,
            raw_type: self.raw_type,
            symbol_index: self.symbol_index,
        }
    }
}

/// Encoded writes for one mapping, with relocation diagnostics retained.
#[must_use = "apply the validated writes to finish relocation"]
pub(crate) struct RelocationWrites {
    image_start: TargetAddress,
    width: usize,
    writes: Vec<PlannedWrite>,
}

/// Resolve and validate the complete batch before modifying the mapping.
/// The resolver returns a final value or `None` for a no-op record.
pub(crate) fn plan(
    allocation: &impl ImageMapping,
    class: ElfClass,
    endian: ElfData,
    segments: &[LoadSegmentInfo],
    image_start: TargetAddress,
    records: &[RelocationRecord],
    mut resolve: impl FnMut(&RelocationRecord) -> LoadResult<Option<i128>>,
) -> LoadResult<RelocationWrites> {
    let width = match class {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    };
    let mut writes = Vec::new();
    for record in records {
        let Some(value) = resolve(record)? else {
            continue;
        };
        validate_target(allocation, segments, image_start, record, width as u64)?;
        let bytes = encode(value, class, endian)
            .ok_or_else(|| LoadError::relocation(record, LoadErrorKind::IntegerOverflow))?;
        writes
            .try_reserve(1)
            .map_err(|_| LoadError::relocation(record, LoadErrorKind::OutOfMemory))?;
        writes.push(PlannedWrite {
            target: record.offset(),
            raw_type: record.raw_type(),
            symbol_index: record.symbol_index(),
            bytes,
        });
    }

    writes.sort_unstable_by_key(|write| write.target);
    for pair in writes.windows(2) {
        let (previous, next) = (&pair[0], &pair[1]);
        if next.target.get() - previous.target.get() < width as u64 {
            return Err(LoadError::new(LoadErrorKind::BadElf, next.context()));
        }
    }
    Ok(RelocationWrites {
        image_start,
        width,
        writes,
    })
}

impl RelocationWrites {
    /// Apply the batch to the mapping used to plan it.
    pub(crate) fn apply(self, allocation: &mut impl ImageMapping) -> LoadResult<()> {
        for write in self.writes {
            // Planning established that the target address is at or above image_start.
            let offset = AllocationOffset::new(write.target.get() - self.image_start.get());
            allocation
                .write(offset, &write.bytes[..self.width])
                .map_err(|error| error.with_context(write.context()))?;
        }
        Ok(())
    }
}

fn validate_target(
    allocation: &impl ImageMapping,
    segments: &[LoadSegmentInfo],
    image_start: TargetAddress,
    record: &RelocationRecord,
    width: u64,
) -> LoadResult<()> {
    let target = record.offset();
    let fail = |kind| LoadError::relocation(record, kind);
    if !target.get().is_multiple_of(width) {
        return Err(fail(LoadErrorKind::InvalidAlignment));
    }
    let segment = segments
        .iter()
        .find(|segment| {
            TargetRange::new(segment.vaddr(), segment.memory_size()).contains_span(target, width)
        })
        .ok_or_else(|| fail(LoadErrorKind::OutOfBounds))?;
    if !segment.permissions().contains(MemoryPermissions::WRITE) {
        return Err(fail(LoadErrorKind::PermissionConflict));
    }
    let offset = target
        .checked_sub(image_start)
        .map_err(|_| fail(LoadErrorKind::OutOfBounds))?;
    if offset
        .checked_add(width)
        .is_none_or(|end| end > allocation.len())
    {
        return Err(fail(LoadErrorKind::OutOfBounds));
    }
    let runtime = allocation
        .base()
        .checked_add(offset)
        .map_err(|_| fail(LoadErrorKind::IntegerOverflow))?;
    runtime
        .checked_add(width)
        .map_err(|_| fail(LoadErrorKind::IntegerOverflow))?;
    if !runtime.get().is_multiple_of(width) {
        return Err(fail(LoadErrorKind::InvalidAlignment));
    }
    Ok(())
}

fn encode(value: i128, class: ElfClass, endian: ElfData) -> Option<[u8; 8]> {
    match class {
        ElfClass::Elf32 => {
            let value = u32::try_from(value).ok()?;
            let word = match endian {
                ElfData::Little => value.to_le_bytes(),
                ElfData::Big => value.to_be_bytes(),
            };
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&word);
            Some(bytes)
        }
        ElfClass::Elf64 => {
            let value = u64::try_from(value).ok()?;
            Some(match endian {
                ElfData::Little => value.to_le_bytes(),
                ElfData::Big => value.to_be_bytes(),
            })
        }
    }
}
