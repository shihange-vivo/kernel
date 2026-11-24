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

//! Bound dynamic symbol counts using SysV and GNU hash metadata.

use goblin::elf::dynamic::{DT_GNU_HASH, DT_HASH};

use super::{
    read_u32, segment::vaddr_to_file_range, ElfClass, ElfData, FileRange, LoadSegmentInfo,
};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::TargetAddress,
    ElfReader, LoadError, LoadResult,
};

pub(super) const SYSV_HASH_HEADER_SIZE: u64 = 8;
pub(super) const GNU_HASH_HEADER_SIZE: u64 = 16;

/// SysV hash has one 32-bit chain entry per dynamic symbol in either ELF class.
pub(super) fn read_sysv_symbol_count(
    reader: &impl ElfReader,
    segments: &[LoadSegmentInfo],
    address: TargetAddress,
    endian: ElfData,
) -> LoadResult<u32> {
    let bad_hash = || bad_hash(DT_HASH, address);
    let header =
        vaddr_to_file_range(segments, address, SYSV_HASH_HEADER_SIZE).ok_or_else(bad_hash)?;
    let mut raw = [0; SYSV_HASH_HEADER_SIZE as usize];
    reader.read_exact_at(header.offset(), &mut raw)?;
    let nbucket = read_u32(&raw, 0, endian)?;
    let nchain = read_u32(&raw, 4, endian)?;
    if nbucket == 0 || nchain == 0 {
        return Err(bad_hash());
    }
    let len = SYSV_HASH_HEADER_SIZE + 4 * (u64::from(nbucket) + u64::from(nchain));
    vaddr_to_file_range(segments, address, len).ok_or_else(bad_hash)?;
    Ok(nchain)
}

/// Find the last symbol through the highest nonempty GNU bucket.
/// Empty buckets provide no independent symbol count.
pub(super) fn read_gnu_symbol_count(
    reader: &impl ElfReader,
    file: FileRange,
    address: TargetAddress,
    class: ElfClass,
    endian: ElfData,
    max_symbols: u32,
) -> LoadResult<Option<u32>> {
    let bad = || bad_hash(DT_GNU_HASH, address);
    if file.len() < GNU_HASH_HEADER_SIZE {
        return Err(bad());
    }
    let mut header = [0; GNU_HASH_HEADER_SIZE as usize];
    reader.read_exact_at(file.offset(), &mut header)?;
    let nbucket = read_u32(&header, 0, endian)?;
    let symbol_offset = read_u32(&header, 4, endian)?;
    let bloom_words = read_u32(&header, 8, endian)?;
    let bloom_shift = read_u32(&header, 12, endian)?;
    if nbucket == 0
        || symbol_offset == 0
        || !bloom_words.is_power_of_two()
        || bloom_shift >= u32::BITS
    {
        return Err(bad());
    }

    let bloom_word_size = match class {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    };
    let bucket_start = GNU_HASH_HEADER_SIZE + u64::from(bloom_words) * bloom_word_size;
    let bucket_len = u64::from(nbucket) * 4;
    let chain_start = bucket_start + bucket_len;
    if chain_start > file.len() {
        return Err(bad());
    }

    let mut highest = 0;
    let buckets = FileRange::new(file.offset() + bucket_start, bucket_len);
    scan_words(reader, buckets, endian, |bucket| {
        if bucket != 0 && !(symbol_offset..max_symbols).contains(&bucket) {
            return Err(bad());
        }
        highest = highest.max(bucket);
        Ok(false)
    })?;
    if highest == 0 {
        return Ok(None);
    }

    let start = chain_start + u64::from(highest - symbol_offset) * 4;
    let available_words = file.len().saturating_sub(start) / 4;
    let words = available_words.min(u64::from(max_symbols - highest));
    if words == 0 {
        return Err(bad());
    }
    let chain = FileRange::new(file.offset() + start, words * 4);
    let last = scan_words(reader, chain, endian, |word| Ok(word & 1 != 0))?.ok_or_else(bad)?;
    let count = u32::try_from(u64::from(highest) + last + 1).map_err(|_| bad())?;
    Ok(Some(count))
}

fn scan_words(
    reader: &impl ElfReader,
    file: FileRange,
    endian: ElfData,
    mut stop: impl FnMut(u32) -> LoadResult<bool>,
) -> LoadResult<Option<u64>> {
    let mut buffer = [0; 128];
    let mut offset = 0;
    while offset < file.len() {
        let len = (file.len() - offset).min(buffer.len() as u64) as usize;
        let bytes = &mut buffer[..len];
        reader.read_exact_at(file.offset() + offset, bytes)?;
        for (index, word) in bytes.chunks_exact(4).enumerate() {
            if stop(read_u32(word, 0, endian)?)? {
                return Ok(Some(offset / 4 + index as u64));
            }
        }
        offset += len as u64;
    }
    Ok(None)
}

fn bad_hash(tag: u64, address: TargetAddress) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag {
            tag,
            value: address.get(),
        },
    )
}
