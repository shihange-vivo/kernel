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

//! Dynamic hash layouts and bounded traversal of symbol candidates.

use goblin::elf::dynamic::{DT_GNU_HASH, DT_HASH};

use super::{
    read_u32, read_u64, segment::vaddr_to_file_range, ElfClass, ElfData, FileRange, LoadSegmentInfo,
};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::TargetAddress,
    ElfReader, LoadError, LoadResult,
};

pub(super) const SYSV_HASH_HEADER_SIZE: u64 = 8;
pub(super) const GNU_HASH_HEADER_SIZE: u64 = 16;

pub(super) struct SysvHash {
    address: TargetAddress,
    file_offset: u64,
    nbucket: u32,
    count: u32,
}

impl SysvHash {
    /// SysV hash has one 32-bit chain entry per dynamic symbol in either ELF class.
    pub(super) fn read(
        reader: &impl ElfReader,
        segments: &[LoadSegmentInfo],
        address: TargetAddress,
        endian: ElfData,
    ) -> LoadResult<Self> {
        let bad = || bad_hash(DT_HASH, address);
        let header =
            vaddr_to_file_range(segments, address, SYSV_HASH_HEADER_SIZE).ok_or_else(bad)?;
        let mut raw = [0; SYSV_HASH_HEADER_SIZE as usize];
        reader.read_exact_at(header.offset(), &mut raw)?;
        let nbucket = read_u32(&raw, 0, endian)?;
        let count = read_u32(&raw, 4, endian)?;
        if nbucket == 0 || count == 0 {
            return Err(bad());
        }
        let len = SYSV_HASH_HEADER_SIZE + 4 * (u64::from(nbucket) + u64::from(count));
        vaddr_to_file_range(segments, address, len).ok_or_else(bad)?;
        Ok(Self {
            address,
            file_offset: header.offset(),
            nbucket,
            count,
        })
    }

    pub(super) const fn count(&self) -> u32 {
        self.count
    }

    pub(super) fn find_candidate<T>(
        &self,
        reader: &impl ElfReader,
        endian: ElfData,
        name: &[u8],
        mut find: impl FnMut(u32) -> LoadResult<Option<T>>,
    ) -> LoadResult<Option<T>> {
        let buckets = self.file_offset + SYSV_HASH_HEADER_SIZE;
        let chains = buckets + 4 * u64::from(self.nbucket);
        let bucket_offset = buckets + 4 * u64::from(sysv_hash(name) % self.nbucket);
        let mut index = read_word(reader, bucket_offset, endian)?;
        // A valid chain visits at most count - 1 nonzero symbol indices.
        for _ in 1..self.count {
            if index == 0 {
                return Ok(None);
            }
            if index >= self.count {
                return Err(bad_hash(DT_HASH, self.address));
            }
            if let Some(candidate) = find(index)? {
                return Ok(Some(candidate));
            }
            index = read_word(reader, chains + 4 * u64::from(index), endian)?;
        }
        if index == 0 {
            return Ok(None);
        }
        Err(bad_hash(DT_HASH, self.address))
    }
}

pub(super) struct GnuHash {
    address: TargetAddress,
    file_offset: u64,
    nbucket: u32,
    symbol_offset: u32,
    bloom_words: u32,
    bloom_shift: u32,
}

impl GnuHash {
    /// Find the last symbol through the highest nonempty GNU bucket.
    /// Empty buckets provide no independent symbol count.
    pub(super) fn read(
        reader: &impl ElfReader,
        file: FileRange,
        address: TargetAddress,
        class: ElfClass,
        endian: ElfData,
        max_symbols: u32,
    ) -> LoadResult<(Self, Option<u32>)> {
        let bad = || bad_hash(DT_GNU_HASH, address);
        if file.len() < GNU_HASH_HEADER_SIZE {
            return Err(bad());
        }
        let mut header = [0; GNU_HASH_HEADER_SIZE as usize];
        reader.read_exact_at(file.offset(), &mut header)?;
        let hash = Self {
            address,
            file_offset: file.offset(),
            nbucket: read_u32(&header, 0, endian)?,
            symbol_offset: read_u32(&header, 4, endian)?,
            bloom_words: read_u32(&header, 8, endian)?,
            bloom_shift: read_u32(&header, 12, endian)?,
        };
        if hash.nbucket == 0
            || hash.symbol_offset == 0
            || !hash.bloom_words.is_power_of_two()
            || hash.bloom_shift >= u32::BITS
        {
            return Err(bad());
        }

        let bucket_start = hash.bucket_start(class);
        let chain_start = hash.chain_start(class);
        if chain_start > file.len() {
            return Err(bad());
        }

        let mut highest = 0;
        let buckets = FileRange::new(file.offset() + bucket_start, chain_start - bucket_start);
        scan_words(reader, buckets, endian, |bucket| {
            if bucket != 0 && !(hash.symbol_offset..max_symbols).contains(&bucket) {
                return Err(bad());
            }
            highest = highest.max(bucket);
            Ok(false)
        })?;
        if highest == 0 {
            return Ok((hash, None));
        }

        let start = chain_start + u64::from(highest - hash.symbol_offset) * 4;
        let available_words = file.len().saturating_sub(start) / 4;
        let words = available_words.min(u64::from(max_symbols - highest));
        if words == 0 {
            return Err(bad());
        }
        let chain = FileRange::new(file.offset() + start, words * 4);
        let last = scan_words(reader, chain, endian, |word| Ok(word & 1 != 0))?.ok_or_else(bad)?;
        let count = u32::try_from(u64::from(highest) + last + 1).map_err(|_| bad())?;
        Ok((hash, Some(count)))
    }

    pub(super) fn find_candidate<T>(
        &self,
        reader: &impl ElfReader,
        class: ElfClass,
        endian: ElfData,
        count: u32,
        name: &[u8],
        mut find: impl FnMut(u32) -> LoadResult<Option<T>>,
    ) -> LoadResult<Option<T>> {
        let hash = gnu_hash(name);
        if !self.bloom_may_match(reader, class, endian, hash)? {
            return Ok(None);
        }
        let buckets = self.file_offset + self.bucket_start(class);
        let first = read_word(reader, buckets + 4 * u64::from(hash % self.nbucket), endian)?;
        if first == 0 {
            return Ok(None);
        }
        if !(self.symbol_offset..count).contains(&first) {
            return Err(self.bad());
        }

        let chains = self.file_offset + self.chain_start(class);
        for index in first..count {
            let word = read_word(
                reader,
                chains + 4 * u64::from(index - self.symbol_offset),
                endian,
            )?;
            if word & !1 == hash & !1
                && let Some(candidate) = find(index)?
            {
                return Ok(Some(candidate));
            }
            if word & 1 != 0 {
                return Ok(None);
            }
        }
        Err(self.bad())
    }

    fn bloom_may_match(
        &self,
        reader: &impl ElfReader,
        class: ElfClass,
        endian: ElfData,
        hash: u32,
    ) -> LoadResult<bool> {
        let size = bloom_word_size(class) as usize;
        let bits = size as u32 * 8;
        let index = (hash / bits) & (self.bloom_words - 1);
        let offset = self.file_offset + GNU_HASH_HEADER_SIZE + u64::from(index) * size as u64;
        let mut raw = [0; 8];
        reader.read_exact_at(offset, &mut raw[..size])?;
        let word = match class {
            ElfClass::Elf32 => u64::from(read_u32(&raw, 0, endian)?),
            ElfClass::Elf64 => read_u64(&raw, 0, endian)?,
        };
        let mask = (1u64 << (hash % bits)) | (1u64 << ((hash >> self.bloom_shift) % bits));
        Ok(word & mask == mask)
    }

    fn bucket_start(&self, class: ElfClass) -> u64 {
        GNU_HASH_HEADER_SIZE + u64::from(self.bloom_words) * bloom_word_size(class)
    }

    fn chain_start(&self, class: ElfClass) -> u64 {
        self.bucket_start(class) + 4 * u64::from(self.nbucket)
    }

    fn bad(&self) -> LoadError {
        bad_hash(DT_GNU_HASH, self.address)
    }
}

fn bloom_word_size(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    }
}

fn read_word(reader: &impl ElfReader, offset: u64, endian: ElfData) -> LoadResult<u32> {
    let mut raw = [0; 4];
    reader.read_exact_at(offset, &mut raw)?;
    read_u32(&raw, 0, endian)
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

fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in name {
        hash = (hash << 4).wrapping_add(u32::from(byte));
        let high = hash & 0xf000_0000;
        hash ^= (high >> 24) | high;
    }
    hash
}

fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381_u32, |hash, &byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(byte))
    })
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
