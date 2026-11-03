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

//! Dynamic symbol table decoding and hash lookup.
//!
//! A [`SymbolTable`] owns a copy of the validated `.dynstr` bytes and the
//! decoded symbol entries. The symbol count is always *proven* from a SysV
//! `DT_HASH` or GNU `DT_GNU_HASH` table — never inferred from section headers
//! or from the tail of a segment. Lookup checks the ELF hash result against
//! an owned, sorted name index in logarithmic time. A bounded linear scan is
//! kept only as a test oracle.

use alloc::{boxed::Box, vec::Vec};

use crate::{
    elf::{read_u16, read_u32, read_u64, LoadSegmentInfo},
    error::{ErrorContext, LoadErrorKind},
    memory::{
        address::{TargetAddress, TargetRange},
        MemoryPermissions,
    },
    profile::{ElfClass, ElfData},
    LoadError, LoadResult,
};

/// ELF symbol binding (`STB_*`). OS/processor-specific bindings are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolBinding {
    Local,
    Global,
    Weak,
}

/// ELF symbol visibility (`STV_*`). `STV_DEFAULT`/`HIDDEN`/`PROTECTED`/`INTERNAL`
/// are understood; the reserved/elimination values are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolVisibility {
    Default,
    Protected,
    Hidden,
    Internal,
}

/// ELF symbol type (`STT_*`). The first release supports the three meaningful
/// relocation targets plus `Section`; TLS/IFUNC/file/common are rejected.
///
/// `Section` is never a binding target -- it is always `STB_LOCAL` -- but bfd
/// exports the section symbols of a PIE into `.dynsym`, so refusing the type
/// would refuse every GNU-ld-linked image. It is accepted and then ignored by
/// the scopes, which only ever bind `Global`/`Weak`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
}

/// Whether a symbol is defined in this image or imported from elsewhere.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolDefinition {
    Defined,
    Undefined,
}

/// One decoded `.dynsym` entry. `name_offset`/`name_len` index into the
/// table's owned `.dynstr` copy; `value` is already load-biased to a runtime
/// address for defined symbols (bit 0 of a Thumb function is preserved).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SymbolEntry {
    name_offset: u32,
    name_len: u32,
    value: TargetAddress,
    size: u64,
    binding: SymbolBinding,
    visibility: SymbolVisibility,
    symbol_type: SymbolType,
    definition: SymbolDefinition,
    absolute: bool,
}

impl SymbolEntry {
    #[inline]
    pub(crate) const fn name_offset(&self) -> u32 {
        self.name_offset
    }

    #[inline]
    pub(crate) const fn name_len(&self) -> u32 {
        self.name_len
    }

    #[inline]
    pub(crate) const fn value(&self) -> TargetAddress {
        self.value
    }

    #[inline]
    pub(crate) const fn size(&self) -> u64 {
        self.size
    }

    #[inline]
    pub(crate) const fn binding(&self) -> SymbolBinding {
        self.binding
    }

    #[inline]
    pub(crate) const fn visibility(&self) -> SymbolVisibility {
        self.visibility
    }

    #[inline]
    pub(crate) const fn symbol_type(&self) -> SymbolType {
        self.symbol_type
    }

    #[inline]
    pub(crate) const fn definition(&self) -> SymbolDefinition {
        self.definition
    }

    #[inline]
    pub(crate) const fn is_absolute(&self) -> bool {
        self.absolute
    }
}

/// GNU ELF string hash (`DT_GNU_HASH`), over raw bytes.
pub(crate) fn gnu_hash(name: &[u8]) -> u32 {
    const SEED: u32 = 5381;
    name.iter().fold(SEED, |hash, &byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(byte))
    })
}

/// SysV ELF string hash (`DT_HASH`), over raw bytes.
pub(crate) fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(u32::from(byte));
        let g = hash & 0xf000_0000;
        if g != 0 {
            hash ^= g >> 24;
        }
        hash &= !g;
    }
    hash
}

/// Validated SysV hash table. The symbol count is `nchain`.
#[derive(Clone)]
struct SysVHash {
    nbucket: u32,
    buckets: Vec<u32>,
    chains: Vec<u32>,
}

impl SysVHash {
    /// Parse a complete `DT_HASH` table. Returns the table and the symbol
    /// count (`nchain`). Every bucket/chain link is validated in-bounds so a
    /// later lookup can never index out of range.
    fn parse(bytes: &[u8], endian: ElfData) -> LoadResult<(Self, u32)> {
        if bytes.len() < 8 {
            return Err(hash_error());
        }
        let nbucket = read_u32(bytes, 0, endian)?;
        let nchain = read_u32(bytes, 4, endian)?;
        if nbucket == 0 || nchain == 0 {
            return Err(hash_error());
        }
        let expected = 8u64
            .checked_add(4u64 * (u64::from(nbucket) + u64::from(nchain)))
            .ok_or_else(hash_error)?;
        if u64::try_from(bytes.len()).map_err(|_| hash_error())? != expected {
            return Err(hash_error());
        }
        let mut buckets = Vec::new();
        buckets
            .try_reserve_exact(nbucket as usize)
            .map_err(|_| hash_oom())?;
        let mut chains = Vec::new();
        chains
            .try_reserve_exact(nchain as usize)
            .map_err(|_| hash_oom())?;
        for index in 0..nbucket {
            let bucket = read_u32(bytes, 8 + 4 * index as usize, endian)?;
            if bucket >= nchain && bucket != 0 {
                return Err(hash_error());
            }
            buckets.push(bucket);
        }
        let chain_base = 8 + 4 * nbucket as usize;
        for index in 0..nchain {
            let link = read_u32(bytes, chain_base + 4 * index as usize, endian)?;
            if link >= nchain {
                return Err(hash_error());
            }
            chains.push(link);
        }

        // Prove that every bucket-reachable chain terminates at STN_UNDEF.
        // Valid buckets have disjoint chains. A whole-table budget rejects
        // cycles and bounds repeated walks without auxiliary allocation.
        let mut remaining = chains.len();
        for &bucket in &buckets {
            let mut index = bucket;
            while index != 0 {
                remaining = remaining.checked_sub(1).ok_or_else(hash_error)?;
                index = chains[index as usize];
            }
        }
        Ok((
            Self {
                nbucket,
                buckets,
                chains,
            },
            nchain,
        ))
    }

    fn lookup(
        &self,
        name: &[u8],
        hash: u32,
        dynstr: &[u8],
        entries: &[SymbolEntry],
    ) -> Option<u32> {
        if self.nbucket == 0 {
            return None;
        }
        let mut index = self.buckets[(hash % self.nbucket) as usize];
        let mut remaining = self.chains.len();
        while index != 0 {
            if remaining == 0 {
                return None;
            }
            remaining -= 1;
            let entry = entries.get(index as usize)?;
            if name_matches(dynstr, entry, name) {
                return Some(index);
            }
            index = *self.chains.get(index as usize)?;
        }
        None
    }
}

/// Validated GNU hash table. The symbol count is `symndx + chains.len()`.
#[derive(Clone)]
struct GnuHash {
    symndx: u32,
    shift2: u32,
    class_bits: u32,
    bloom: Vec<u64>,
    buckets: Vec<u32>,
    chains: Vec<u32>,
}

impl GnuHash {
    /// Parse a complete `DT_GNU_HASH` table. Returns the table and the symbol
    /// count. `maskwords` must be a power of two and every bucket must reach a
    /// terminating chain word. The highest reachable terminator must be the
    /// final supplied word, so padding cannot inflate the symbol count.
    fn parse(bytes: &[u8], endian: ElfData, class: ElfClass) -> LoadResult<(Self, u32)> {
        if bytes.len() < 16 {
            return Err(hash_error());
        }
        let nbuckets = read_u32(bytes, 0, endian)?;
        let symndx = read_u32(bytes, 4, endian)?;
        let maskwords = read_u32(bytes, 8, endian)?;
        let shift2 = read_u32(bytes, 12, endian)?;
        if nbuckets == 0 || !maskwords.is_power_of_two() || maskwords == 0 || shift2 >= u32::BITS {
            return Err(hash_error());
        }
        let class_bits: u32 = match class {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 64,
        };
        let word_size = class_bits / 8;
        let bloom_bytes = u64::from(maskwords) * u64::from(word_size);
        let buckets_bytes = u64::from(nbuckets) * 4;
        let head = 16u64
            .checked_add(bloom_bytes)
            .and_then(|v| v.checked_add(buckets_bytes))
            .ok_or_else(hash_error)?;
        let total = u64::try_from(bytes.len()).map_err(|_| hash_error())?;
        if total < head {
            return Err(hash_error());
        }
        let chains_bytes = total - head;
        if chains_bytes % 4 != 0 {
            return Err(hash_error());
        }
        let chain_count = u32::try_from(chains_bytes / 4).map_err(|_| hash_error())?;
        let symbol_count = symndx.checked_add(chain_count).ok_or_else(hash_error)?;

        let mut bloom = Vec::new();
        bloom
            .try_reserve_exact(maskwords as usize)
            .map_err(|_| hash_oom())?;
        for index in 0..maskwords as usize {
            let offset = 16 + index * word_size as usize;
            let word = match class {
                ElfClass::Elf32 => u64::from(read_u32(bytes, offset, endian)?),
                ElfClass::Elf64 => read_u64(bytes, offset, endian)?,
            };
            bloom.push(word);
        }
        let mut buckets = Vec::new();
        buckets
            .try_reserve_exact(nbuckets as usize)
            .map_err(|_| hash_oom())?;
        for index in 0..nbuckets as usize {
            let bucket = read_u32(
                bytes,
                16 + maskwords as usize * word_size as usize + 4 * index,
                endian,
            )?;
            if bucket != 0 && (bucket < symndx || bucket >= symbol_count) {
                return Err(hash_error());
            }
            buckets.push(bucket);
        }
        let mut chains = Vec::new();
        chains
            .try_reserve_exact(chain_count as usize)
            .map_err(|_| hash_oom())?;
        let chain_base = 16 + maskwords as usize * word_size as usize + nbuckets as usize * 4;
        for index in 0..chain_count as usize {
            chains.push(read_u32(bytes, chain_base + 4 * index, endian)?);
        }

        // Valid bucket chains are disjoint. Sharing one budget prevents
        // repeated or overlapping chains from multiplying validation work.
        let mut remaining = chains.len();
        let mut highest_end = None;
        for &bucket in &buckets {
            if bucket == 0 {
                continue;
            }
            let mut index = (bucket - symndx) as usize;
            loop {
                remaining = remaining.checked_sub(1).ok_or_else(hash_error)?;
                let chain = *chains.get(index).ok_or_else(hash_error)?;
                if chain & 1 != 0 {
                    highest_end = Some(highest_end.map_or(index, |end| core::cmp::max(end, index)));
                    break;
                }
                index = index.checked_add(1).ok_or_else(hash_error)?;
            }
        }
        let exact_extent = match highest_end {
            Some(index) => index.checked_add(1) == Some(chains.len()),
            None => chains.is_empty(),
        };
        if !exact_extent {
            return Err(hash_error());
        }
        Ok((
            Self {
                symndx,
                shift2,
                class_bits,
                bloom,
                buckets,
                chains,
            },
            symbol_count,
        ))
    }

    fn bloom_may_match(&self, hash: u32) -> bool {
        let mask = self.class_bits - 1;
        let hash2 = hash >> self.shift2;
        let bitmask: u64 = (1u64 << (hash & mask)) | (1u64 << (hash2 & mask));
        let bloom_index = ((hash / self.class_bits) & ((self.bloom.len() as u32) - 1)) as usize;
        (self.bloom[bloom_index] & bitmask) == bitmask
    }

    fn lookup(
        &self,
        name: &[u8],
        hash: u32,
        dynstr: &[u8],
        entries: &[SymbolEntry],
    ) -> Option<u32> {
        if self.buckets.is_empty() {
            return None;
        }
        let bucket = self.buckets[(hash % self.buckets.len() as u32) as usize];
        if bucket < self.symndx || !self.bloom_may_match(hash) {
            return None;
        }
        let mut index = (bucket - self.symndx) as usize;
        while index < self.chains.len() {
            let chain = self.chains[index];
            if chain & !1 == hash & !1 {
                let symbol_index = self.symndx + index as u32;
                if symbol_index < entries.len() as u32
                    && name_matches(dynstr, &entries[symbol_index as usize], name)
                {
                    return Some(symbol_index);
                }
            }
            if chain & 1 == 1 {
                break;
            }
            index += 1;
        }
        None
    }
}

/// Owned, validated `.dynstr` plus the decoded symbol entries.
#[derive(Clone)]
pub(crate) struct SymbolTable {
    dynstr: Vec<u8>,
    entries: Vec<SymbolEntry>,
    name_index: Vec<u32>,
    gnu: Option<GnuHash>,
    sysv: Option<SysVHash>,
}

impl SymbolTable {
    /// An empty table for images that carry no `DT_SYMTAB`.
    pub(crate) fn empty() -> Self {
        Self {
            dynstr: Vec::new(),
            entries: Vec::new(),
            name_index: Vec::new(),
            gnu: None,
            sysv: None,
        }
    }

    /// Decode the dynamic symbol table.
    ///
    /// `symtab` holds the `DT_SYMTAB` bytes (`symbol_count * syment`), `dynstr`
    /// the validated `DT_STRTAB` bytes. The symbol count is proven from the
    /// hash table(s) — the two tables must agree when both are present. Every
    /// defined symbol's `st_value`/`st_size` is checked against the load
    /// segments, and unsupported binding/type/visibility/`st_shndx` fail closed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode(
        symtab: &[u8],
        dynstr: Vec<u8>,
        class: ElfClass,
        endian: ElfData,
        load_bias: TargetAddress,
        segments: &[LoadSegmentInfo],
        thumb: bool,
        max_symbol_name_len: u32,
        gnu_bytes: Option<Vec<u8>>,
        sysv_bytes: Option<Vec<u8>>,
    ) -> LoadResult<Self> {
        let syment: usize = match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };

        let (gnu, gnu_count) = match gnu_bytes {
            Some(bytes) => {
                let (table, count) = GnuHash::parse(&bytes, endian, class)?;
                (Some(table), count)
            }
            None => (None, 0),
        };
        let (sysv, sysv_count) = match sysv_bytes {
            Some(bytes) => {
                let (table, count) = SysVHash::parse(&bytes, endian)?;
                (Some(table), count)
            }
            None => (None, 0),
        };

        // The count must be provable, and the two tables must agree.
        let symbol_count = match (gnu.as_ref(), sysv.as_ref()) {
            (Some(_), Some(_)) => {
                if gnu_count != sysv_count {
                    return Err(hash_error());
                }
                gnu_count
            }
            (Some(_), None) => gnu_count,
            (None, Some(_)) => sysv_count,
            (None, None) => return Err(hash_error()),
        };

        let expected = u64::from(symbol_count)
            .checked_mul(syment as u64)
            .ok_or_else(hash_error)?;
        if u64::try_from(symtab.len()).map_err(|_| hash_error())? != expected {
            return Err(hash_error());
        }

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(symbol_count as usize)
            .map_err(|_| hash_oom())?;
        for index in 0..symbol_count as usize {
            let raw = &symtab[index * syment..(index + 1) * syment];
            let entry = parse_symbol_entry(
                raw,
                class,
                endian,
                load_bias,
                segments,
                thumb,
                max_symbol_name_len,
                index as u32,
                &dynstr,
            )?;
            entries.push(entry);
        }

        let mut table = Self {
            dynstr,
            entries,
            name_index: Vec::new(),
            gnu,
            sysv,
        };
        table.name_index = table.build_name_index()?;
        Ok(table)
    }

    /// Build from decoded names, independently of the untrusted hash tables.
    /// Keep the lowest symbol index for duplicate names, matching a linear
    /// scan even when a hash chain omits or reorders the first occurrence.
    fn build_name_index(&self) -> LoadResult<Vec<u32>> {
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(self.entries.len())
            .map_err(|_| hash_oom())?;
        indices.extend(0..self.symbol_count());
        let name = |index: u32| self.name(&self.entries[index as usize]);
        indices.sort_unstable_by(|left, right| {
            name(*left).cmp(name(*right)).then_with(|| left.cmp(right))
        });
        indices.dedup_by(|left, right| name(*left) == name(*right));
        Ok(indices)
    }

    #[inline]
    pub(crate) fn symbol_count(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Total owned metadata bytes kept by this table: the `.dynstr` copy, the
    /// decoded symbol entries, sorted name index and retained hash tables.
    /// Charged against `max_runtime_metadata_bytes`. Overflow saturates at
    /// `u64::MAX`.
    pub(crate) fn metadata_bytes(&self) -> u64 {
        let dynstr = self.dynstr.len() as u64;
        let entries =
            (self.entries.len() as u64).saturating_mul(core::mem::size_of::<SymbolEntry>() as u64);
        let name_index =
            (self.name_index.capacity() as u64).saturating_mul(core::mem::size_of::<u32>() as u64);
        let sysv = self.sysv.as_ref().map_or(0, |table| {
            (table.buckets.len() as u64)
                .saturating_add(table.chains.len() as u64)
                .saturating_mul(4)
        });
        let gnu = self.gnu.as_ref().map_or(0, |table| {
            (table.bloom.len() as u64)
                .saturating_mul(core::mem::size_of::<u64>() as u64)
                .saturating_add(
                    (table.buckets.len() as u64)
                        .saturating_add(table.chains.len() as u64)
                        .saturating_mul(4),
                )
        });
        dynstr
            .checked_add(entries)
            .and_then(|v| v.checked_add(name_index))
            .and_then(|v| v.checked_add(sysv))
            .and_then(|v| v.checked_add(gnu))
            .unwrap_or(u64::MAX)
    }

    #[inline]
    pub(crate) fn entry(&self, index: u32) -> Option<&SymbolEntry> {
        self.entries.get(index as usize)
    }

    #[inline]
    pub(crate) fn entries(&self) -> &[SymbolEntry] {
        &self.entries
    }

    /// The NUL-free name bytes of a symbol entry, indexed into the owned
    /// `.dynstr`.
    #[inline]
    pub(crate) fn name(&self, entry: &SymbolEntry) -> &[u8] {
        let start = entry.name_offset() as usize;
        let end = start + entry.name_len() as usize;
        &self.dynstr[start..end]
    }

    /// Check the hash result against the first matching decoded symbol.
    pub(crate) fn lookup(&self, name: &[u8]) -> Option<u32> {
        let hashed = match (&self.gnu, &self.sysv) {
            (Some(gnu), Some(sysv)) => {
                let gnu = gnu.lookup(name, gnu_hash(name), &self.dynstr, &self.entries);
                let sysv = sysv.lookup(name, sysv_hash(name), &self.dynstr, &self.entries);
                if gnu == sysv {
                    gnu
                } else {
                    None
                }
            }
            (Some(gnu), None) => gnu.lookup(name, gnu_hash(name), &self.dynstr, &self.entries),
            (None, Some(sysv)) => sysv.lookup(name, sysv_hash(name), &self.dynstr, &self.entries),
            (None, None) => return self.lookup_indexed(name),
        }?;
        if self.lookup_indexed(name) == Some(hashed) {
            Some(hashed)
        } else {
            None
        }
    }

    fn lookup_indexed(&self, name: &[u8]) -> Option<u32> {
        self.name_index
            .binary_search_by(|&index| {
                #[cfg(test)]
                tests::NAME_COMPARISONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                self.name(&self.entries[index as usize]).cmp(name)
            })
            .ok()
            .map(|position| self.name_index[position])
    }

    /// Test oracle for the independently built name index.
    #[cfg(test)]
    fn lookup_linear(&self, name: &[u8]) -> Option<u32> {
        self.entries
            .iter()
            .position(|entry| name_matches(&self.dynstr, entry, name))
            .map(|index| index as u32)
    }
}

/// Prove the dynamic symbol count from the available hash table(s).
///
/// The count is never inferred from section headers or a segment tail. When
/// both a SysV `DT_HASH` and a GNU `DT_GNU_HASH` are present their counts must
/// agree. This is the single source of truth the decode stage uses to
/// size the `DT_SYMTAB` read; [`SymbolTable::decode`] re-derives the same count
/// from the identical bytes.
pub(crate) fn symbol_count_from_hash(
    class: ElfClass,
    endian: ElfData,
    gnu_bytes: Option<&[u8]>,
    sysv_bytes: Option<&[u8]>,
) -> LoadResult<u32> {
    let gnu_count = match gnu_bytes {
        Some(bytes) => Some(GnuHash::parse(bytes, endian, class)?.1),
        None => None,
    };
    let sysv_count = match sysv_bytes {
        Some(bytes) => Some(SysVHash::parse(bytes, endian)?.1),
        None => None,
    };
    match (gnu_count, sysv_count) {
        (Some(gnu), Some(sysv)) => {
            if gnu != sysv {
                return Err(hash_error());
            }
            Ok(gnu)
        }
        (Some(gnu), None) => Ok(gnu),
        (None, Some(sysv)) => Ok(sysv),
        (None, None) => Err(hash_error()),
    }
}

#[inline]
fn name_matches(dynstr: &[u8], entry: &SymbolEntry, name: &[u8]) -> bool {
    #[cfg(test)]
    tests::NAME_COMPARISONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let start = entry.name_offset() as usize;
    let end = start + entry.name_len() as usize;
    end <= dynstr.len() && &dynstr[start..end] == name
}

#[allow(clippy::too_many_arguments)]
fn parse_symbol_entry(
    raw: &[u8],
    class: ElfClass,
    endian: ElfData,
    load_bias: TargetAddress,
    segments: &[LoadSegmentInfo],
    thumb: bool,
    max_symbol_name_len: u32,
    index: u32,
    dynstr: &[u8],
) -> LoadResult<SymbolEntry> {
    let (name_offset, value_raw, size_raw, info, other, shndx) = match class {
        ElfClass::Elf32 => (
            read_u32(raw, 0, endian)?,
            u64::from(read_u32(raw, 4, endian)?),
            u64::from(read_u32(raw, 8, endian)?),
            raw[12],
            raw[13],
            read_u16(raw, 14, endian)?,
        ),
        ElfClass::Elf64 => (
            read_u32(raw, 0, endian)?,
            read_u64(raw, 8, endian)?,
            read_u64(raw, 16, endian)?,
            raw[4],
            raw[5],
            read_u16(raw, 6, endian)?,
        ),
    };

    let binding = match info >> 4 {
        0 => SymbolBinding::Local,
        1 => SymbolBinding::Global,
        2 => SymbolBinding::Weak,
        _ => return Err(symbol_error(index, LoadErrorKind::BadElf)),
    };
    let symbol_type = match info & 0xf {
        0 => SymbolType::NoType,
        1 => SymbolType::Object,
        2 => SymbolType::Func,
        3 => SymbolType::Section,
        _ => return Err(symbol_error(index, LoadErrorKind::BadElf)),
    };
    let visibility = match other & 0x7 {
        0 => SymbolVisibility::Default,
        1 => SymbolVisibility::Internal,
        2 => SymbolVisibility::Hidden,
        3 => SymbolVisibility::Protected,
        _ => return Err(symbol_error(index, LoadErrorKind::BadElf)),
    };
    // SHN_COMMON (0xfff2) and reserved/processor indices are unsupported.
    let definition = match shndx {
        0 => SymbolDefinition::Undefined,
        0xfff1 => SymbolDefinition::Defined, // SHN_ABS: absolute, no region check
        0xfff2 => return Err(symbol_error(index, LoadErrorKind::BadElf)),
        1..=0xfeff => {
            // A "definition" that does not land in any of this image's load
            // segments cannot be one of the image's own. GNU ld's bare-metal
            // script PROVIDEs `_stack` (and `.noinit`/`.persistent`), and a PIE
            // linked against a DSO that defines it re-exports the provider's
            // address -- an address this image never maps. Only a dependency
            // can satisfy such a symbol, so record it as undefined and let a
            // lookup bind it there; refusing the whole image over it would
            // reject every GNU-ld-linked PIE. A symbol that *is* used still
            // fails closed, at the bind rather than at the load.
            if symbol_lands_in_segments(segments, symbol_type, thumb, value_raw, size_raw) {
                SymbolDefinition::Defined
            } else {
                SymbolDefinition::Undefined
            }
        }
        _ => return Err(symbol_error(index, LoadErrorKind::BadElf)),
    };

    let (name_offset, name_len) = scan_name(dynstr, name_offset, max_symbol_name_len, index)?;

    let value = match definition {
        SymbolDefinition::Undefined => TargetAddress::new(0),
        SymbolDefinition::Defined => {
            if shndx == 0xfff1 {
                // Absolute symbol: `st_value` is already a runtime address.
                TargetAddress::new(value_raw)
            } else {
                validate_symbol_region(segments, symbol_type, thumb, value_raw, size_raw, index)?;
                // Load-bias applied; bit 0 of a Thumb function is preserved.
                load_bias
                    .checked_add(value_raw)
                    .map_err(|_| symbol_error(index, LoadErrorKind::BadElf))?
            }
        }
    };

    Ok(SymbolEntry {
        name_offset,
        name_len,
        value,
        size: size_raw,
        binding,
        visibility,
        symbol_type,
        definition,
        absolute: shndx == 0xfff1,
    })
}

/// Scan a NUL-terminated name at `offset`, bounded by `max_symbol_name_len`.
/// Returns `(offset, name_len)` with `name_len` excluding the terminator.
fn scan_name(
    dynstr: &[u8],
    offset: u32,
    max_symbol_name_len: u32,
    index: u32,
) -> LoadResult<(u32, u32)> {
    let start = offset as usize;
    if start >= dynstr.len() {
        return Err(symbol_error(index, LoadErrorKind::BadElf));
    }
    let limit = (max_symbol_name_len as usize)
        .checked_add(1)
        .ok_or_else(|| symbol_error(index, LoadErrorKind::BadElf))?;
    let tail = &dynstr[start..];
    let scan = core::cmp::min(limit, tail.len());
    let nul = tail[..scan]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| symbol_error(index, LoadErrorKind::BadElf))?;
    if nul > max_symbol_name_len as usize {
        return Err(symbol_error(index, LoadErrorKind::BadElf));
    }
    Ok((offset, nul as u32))
}

/// A defined symbol must land in a compatible load segment: a function's
/// canonical target in an executable region, an object/notype in a readable
/// region, with `st_size` contained in the same segment.
/// Does a defined symbol's target land in a load segment this image maps with
/// the permission its type requires? A function needs an executable region, an
/// object/notype a readable one, with `st_size` contained in the same segment.
fn symbol_lands_in_segments(
    segments: &[LoadSegmentInfo],
    symbol_type: SymbolType,
    thumb: bool,
    value_raw: u64,
    size_raw: u64,
) -> bool {
    let canonical = if thumb && symbol_type == SymbolType::Func {
        value_raw & !1
    } else {
        value_raw
    };
    let need_execute = symbol_type == SymbolType::Func;
    let span = core::cmp::max(size_raw, 1);
    segments.iter().any(|segment| {
        let permitted = if need_execute {
            segment.permissions().contains(MemoryPermissions::EXECUTE)
        } else {
            segment.permissions().contains(MemoryPermissions::READ)
        };
        permitted
            && TargetRange::new(segment.vaddr(), segment.memory_size())
                .contains_span(TargetAddress::new(canonical), span)
    })
}

fn validate_symbol_region(
    segments: &[LoadSegmentInfo],
    symbol_type: SymbolType,
    thumb: bool,
    value_raw: u64,
    size_raw: u64,
    index: u32,
) -> LoadResult<()> {
    if symbol_lands_in_segments(segments, symbol_type, thumb, value_raw, size_raw) {
        Ok(())
    } else {
        Err(symbol_error(index, LoadErrorKind::BadElf))
    }
}

fn symbol_error(index: u32, kind: LoadErrorKind) -> LoadError {
    LoadError::new(
        kind,
        ErrorContext::Symbol {
            image: 0,
            index,
            name: Box::new([]),
        },
    )
}

fn hash_error() -> LoadError {
    LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
}

fn hash_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;
    use core::sync::atomic::{AtomicUsize, Ordering};

    pub(super) static NAME_COMPARISONS: AtomicUsize = AtomicUsize::new(0);

    fn append_u32(bytes: &mut Vec<u8>, value: u32, endian: ElfData) {
        bytes.extend_from_slice(&match endian {
            ElfData::Little => value.to_le_bytes(),
            ElfData::Big => value.to_be_bytes(),
        });
    }

    fn sysv_bytes(buckets: &[u32], chains: &[u32], endian: ElfData) -> Vec<u8> {
        let size = buckets
            .len()
            .checked_add(chains.len())
            .and_then(|words| words.checked_add(2))
            .and_then(|words| words.checked_mul(4))
            .unwrap();
        let mut bytes = Vec::with_capacity(size);
        append_u32(&mut bytes, u32::try_from(buckets.len()).unwrap(), endian);
        append_u32(&mut bytes, u32::try_from(chains.len()).unwrap(), endian);
        for &word in buckets.iter().chain(chains) {
            append_u32(&mut bytes, word, endian);
        }
        bytes
    }

    fn gnu_bytes(
        buckets: &[u32],
        chains: &[u32],
        symndx: u32,
        class: ElfClass,
        endian: ElfData,
    ) -> Vec<u8> {
        let word_size = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        let size = buckets
            .len()
            .checked_add(chains.len())
            .and_then(|words| words.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(16))
            .and_then(|bytes| bytes.checked_add(word_size))
            .unwrap();
        let mut bytes = Vec::with_capacity(size);
        for word in [u32::try_from(buckets.len()).unwrap(), symndx, 1, 5] {
            append_u32(&mut bytes, word, endian);
        }
        // An all-ones Bloom filter deliberately permits every lookup.
        bytes.resize(bytes.len().checked_add(word_size).unwrap(), 0xff);
        for &word in buckets.iter().chain(chains) {
            append_u32(&mut bytes, word, endian);
        }
        bytes
    }

    #[test]
    fn sysv_hash_rejects_shared_chain_work_amplification() {
        let chains: Vec<u32> = (0..=64u32)
            .map(|index| {
                if index == 0 || index == 64 {
                    0
                } else {
                    index.saturating_add(1)
                }
            })
            .collect();
        for endian in [ElfData::Little, ElfData::Big] {
            for bytes in [
                sysv_bytes(&[1; 64], &chains, endian),
                sysv_bytes(&[1, 2], &[0, 3, 3, 4, 0], endian),
            ] {
                let error = SysVHash::parse(&bytes, endian)
                    .err()
                    .expect("shared chain amplification");
                assert_eq!(error.kind(), LoadErrorKind::BadElf);
            }
        }
    }

    #[test]
    fn sysv_hash_accepts_disjoint_and_long_chains() {
        let chains: Vec<u32> = (0..=64u32)
            .map(|index| {
                if index == 0 || index == 64 {
                    0
                } else {
                    index.saturating_add(1)
                }
            })
            .collect();
        for endian in [ElfData::Little, ElfData::Big] {
            for (buckets, chains) in [
                (&[1, 0, 0][..], chains.as_slice()),
                (&[1, 3, 0][..], &[0, 2, 0, 4, 0][..]),
                (&[0][..], &[0][..]),
            ] {
                let bytes = sysv_bytes(buckets, chains, endian);
                let (_table, count) = SysVHash::parse(&bytes, endian).expect("valid SysV chains");
                assert_eq!(count as usize, chains.len());
            }
        }
    }

    #[test]
    fn sysv_hash_rejects_cycles_and_out_of_range_links() {
        for endian in [ElfData::Little, ElfData::Big] {
            for (buckets, chains) in [
                (&[1][..], &[0, 2, 1][..]),
                (&[1][..], &[0, 1][..]),
                (&[3][..], &[0, 0, 0][..]),
                (&[1][..], &[0, 3, 0][..]),
                (&[][..], &[0][..]),
                (&[0][..], &[][..]),
            ] {
                let bytes = sysv_bytes(buckets, chains, endian);
                let error = SysVHash::parse(&bytes, endian)
                    .err()
                    .expect("invalid SysV table");
                assert_eq!(error.kind(), LoadErrorKind::BadElf);
            }
        }
    }

    #[test]
    fn gnu_hash_rejects_shared_chain_work_amplification() {
        let mut chains = [0x10u32; 64];
        chains[63] |= 1;
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                for bytes in [
                    gnu_bytes(&[1; 64], &chains, 1, class, endian),
                    gnu_bytes(&[7, 8], &[0x10, 0x20, 0x31], 7, class, endian),
                ] {
                    let error = GnuHash::parse(&bytes, endian, class)
                        .err()
                        .expect("shared chain amplification");
                    assert_eq!(error.kind(), LoadErrorKind::BadElf);
                }
            }
        }
    }

    #[test]
    fn gnu_hash_accepts_disjoint_long_and_empty_chains() {
        let mut chains = [0x10u32; 64];
        chains[63] |= 1;
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                for (buckets, chains, symndx) in [
                    (&[1, 0][..], chains.as_slice(), 1u32),
                    (&[3, 0, 5][..], &[0x12, 0x19, 0x1a, 0x21][..], 3),
                    (&[0, 0][..], &[][..], 3),
                ] {
                    let bytes = gnu_bytes(buckets, chains, symndx, class, endian);
                    let (_table, count) =
                        GnuHash::parse(&bytes, endian, class).expect("valid GNU chains");
                    assert_eq!(
                        count as usize,
                        (symndx as usize).checked_add(chains.len()).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn gnu_hash_rejects_missing_terminators_and_unreachable_tail() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                for (buckets, chains, symndx) in [
                    (&[1][..], &[0x10, 0x20][..], 1),
                    (&[1][..], &[0x11, 0x31][..], 1),
                    (&[0][..], &[0x11][..], 1),
                    (&[2][..], &[0x11][..], 3),
                    (&[2][..], &[0x11][..], 1),
                ] {
                    let bytes = gnu_bytes(buckets, chains, symndx, class, endian);
                    let error = GnuHash::parse(&bytes, endian, class)
                        .err()
                        .expect("invalid GNU table");
                    assert_eq!(error.kind(), LoadErrorKind::BadElf);
                }
            }
        }
    }

    fn symbol(name_offset: u32, name_len: u32) -> SymbolEntry {
        SymbolEntry {
            name_offset,
            name_len,
            value: TargetAddress::new(0),
            size: 0,
            binding: if name_offset == 0 {
                SymbolBinding::Local
            } else {
                SymbolBinding::Global
            },
            visibility: SymbolVisibility::Default,
            symbol_type: SymbolType::NoType,
            definition: SymbolDefinition::Undefined,
            absolute: false,
        }
    }

    #[test]
    fn hash_validation_preserves_lookup_and_count_agreement() {
        let dynstr = b"\0alpha\0beta\0gamma\0";
        let entries = [symbol(0, 0), symbol(1, 5), symbol(7, 4), symbol(12, 5)];
        let gnu_chains = [
            gnu_hash(b"alpha") & !1,
            gnu_hash(b"beta") & !1,
            gnu_hash(b"gamma") | 1,
        ];
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                let sysv_raw = sysv_bytes(&[1], &[0, 2, 3, 0], endian);
                let gnu_raw = gnu_bytes(&[1], &gnu_chains, 1, class, endian);
                let (sysv, count) = SysVHash::parse(&sysv_raw, endian).expect("SysV table");
                assert_eq!(count, 4);
                let (gnu, count) = GnuHash::parse(&gnu_raw, endian, class).expect("GNU table");
                assert_eq!(count, 4);
                for (name, expected) in [
                    (&b"alpha"[..], Some(1)),
                    (&b"beta"[..], Some(2)),
                    (&b"gamma"[..], Some(3)),
                    (&b"absent"[..], None),
                ] {
                    assert_eq!(
                        sysv.lookup(name, sysv_hash(name), dynstr, &entries),
                        expected
                    );
                    assert_eq!(gnu.lookup(name, gnu_hash(name), dynstr, &entries), expected);
                }
                assert_eq!(
                    symbol_count_from_hash(class, endian, Some(&gnu_raw), Some(&sysv_raw))
                        .expect("matching counts"),
                    4
                );
                let mismatch = sysv_bytes(&[1], &[0, 2, 3, 4, 0], endian);
                let error = symbol_count_from_hash(class, endian, Some(&gnu_raw), Some(&mismatch))
                    .expect_err("mismatched counts");
                assert_eq!(error.kind(), LoadErrorKind::BadElf);
            }
        }
    }

    fn decoded_symbols(
        dynstr: &[u8],
        offsets: &[u32],
        gnu: Option<Vec<u8>>,
        sysv: Option<Vec<u8>>,
    ) -> SymbolTable {
        let mut symtab = alloc::vec![0; offsets.len().checked_mul(24).unwrap()];
        for (raw, &offset) in symtab.chunks_exact_mut(24).zip(offsets) {
            raw[..4].copy_from_slice(&offset.to_le_bytes());
            // Undefined global symbols need no mapped target allocation.
            raw[4] = if offset == 0 { 0 } else { 0x10 };
        }
        SymbolTable::decode(
            &symtab,
            dynstr.to_vec(),
            ElfClass::Elf64,
            ElfData::Little,
            TargetAddress::new(0),
            &[],
            false,
            256,
            gnu,
            sysv,
        )
        .expect("decode symbol lookup fixture")
    }

    #[test]
    fn name_index_preserves_first_duplicate_and_raw_byte_order() {
        let dynstr = b"\0zeta\0\xff\xfe\0alpha\0zeta\0";
        let offsets = [0, 1, 6, 9, 15];
        let gnu = gnu_bytes(
            &[1],
            &[
                gnu_hash(b"zeta") & !1,
                gnu_hash(b"\xff\xfe") & !1,
                gnu_hash(b"alpha") & !1,
                gnu_hash(b"zeta") | 1,
            ],
            1,
            ElfClass::Elf64,
            ElfData::Little,
        );
        let sysv = sysv_bytes(&[1], &[0, 2, 3, 4, 0], ElfData::Little);
        for (gnu, sysv) in [
            (Some(gnu.clone()), None),
            (None, Some(sysv.clone())),
            (Some(gnu), Some(sysv)),
        ] {
            let table = decoded_symbols(dynstr, &offsets, gnu, sysv);
            assert_eq!(table.name_index, [0, 3, 1, 2]);
            for name in [&b""[..], b"zeta", b"\xff\xfe", b"alpha", b"absent"] {
                assert_eq!(table.lookup_indexed(name), table.lookup_linear(name));
            }
            assert_eq!(table.lookup(b"zeta"), Some(1));
            assert_eq!(table.lookup(b"\xff\xfe"), Some(2));
            assert_eq!(table.lookup(b"alpha"), Some(3));
            assert_eq!(table.lookup(b""), None);
            assert_eq!(table.lookup(b"absent"), None);
        }
        let empty = SymbolTable::empty();
        assert_eq!(empty.lookup(b""), None);
        assert_eq!(empty.lookup(b"absent"), None);
    }

    #[test]
    fn name_index_keeps_malformed_hash_lookups_fail_closed() {
        let dynstr = b"\0dup\0other\0";
        let offsets = [0, 1, 5, 1];
        let chains = [
            gnu_hash(b"dup") & !1,
            gnu_hash(b"other") & !1,
            gnu_hash(b"dup") | 1,
        ];
        let valid_gnu = gnu_bytes(&[1], &chains, 1, ElfClass::Elf64, ElfData::Little);
        let valid_sysv = sysv_bytes(&[1], &[0, 2, 3, 0], ElfData::Little);
        // Structurally bounded tables can still omit/reorder a duplicate,
        // falsify a hash word/Bloom bit, or disagree with the other hash table.
        let reordered_sysv = sysv_bytes(&[3], &[0, 0, 1, 2], ElfData::Little);
        let omitted_gnu = gnu_bytes(&[3], &chains, 1, ElfClass::Elf64, ElfData::Little);
        let mut false_bloom = valid_gnu.clone();
        false_bloom[16..24].fill(0);
        let mut false_hash = chains;
        false_hash[0] = gnu_hash(b"unrelated") & !1;
        let false_hash = gnu_bytes(&[1], &false_hash, 1, ElfClass::Elf64, ElfData::Little);
        for (gnu, sysv) in [
            (None, Some(reordered_sysv)),
            (Some(omitted_gnu.clone()), None),
            (Some(false_bloom), None),
            (Some(false_hash), None),
            (Some(omitted_gnu), Some(valid_sysv)),
            (
                Some(valid_gnu),
                Some(sysv_bytes(&[2], &[0, 0, 0, 0], ElfData::Little)),
            ),
        ] {
            let table = decoded_symbols(dynstr, &offsets, gnu, sysv);
            assert_eq!(table.lookup_indexed(b"dup"), Some(1));
            assert_eq!(table.lookup(b"dup"), None);
            for name in [&b"dup"[..], b"other", b"missing", b""] {
                // Retain exactly the original hash-vs-linear policy.
                let hashed = match (&table.gnu, &table.sysv) {
                    (Some(gnu), Some(sysv)) => {
                        let gnu = gnu.lookup(name, gnu_hash(name), dynstr, &table.entries);
                        let sysv = sysv.lookup(name, sysv_hash(name), dynstr, &table.entries);
                        if gnu == sysv {
                            gnu
                        } else {
                            None
                        }
                    }
                    (Some(gnu), None) => gnu.lookup(name, gnu_hash(name), dynstr, &table.entries),
                    (None, Some(sysv)) => {
                        sysv.lookup(name, sysv_hash(name), dynstr, &table.entries)
                    }
                    (None, None) => panic!("fixture requires a hash table"),
                };
                let expected = if hashed == table.lookup_linear(name) {
                    hashed
                } else {
                    None
                };
                assert_eq!(table.lookup(name), expected);
            }
        }
    }

    #[test]
    fn name_index_charges_capacity_after_deduplication() {
        let mut table = decoded_symbols(
            b"\0dup\0other\0",
            &[0, 1, 5, 1],
            None,
            Some(sysv_bytes(&[1], &[0, 2, 3, 0], ElfData::Little)),
        );
        assert!(table.name_index.len() < table.name_index.capacity());
        let index_bytes = (table.name_index.capacity() as u64)
            .checked_mul(core::mem::size_of::<u32>() as u64)
            .unwrap();
        let total = table.metadata_bytes();
        table.name_index.clear();
        assert_eq!(table.metadata_bytes(), total);
        table.name_index = Vec::new();
        assert_eq!(total.checked_sub(table.metadata_bytes()), Some(index_bytes));
    }

    #[test]
    fn hash_lookup_avoids_full_scans_for_hits_and_misses() {
        let mut dynstr = alloc::vec![0];
        let mut offsets = alloc::vec![0];
        let mut chains = alloc::vec![0];
        for index in 1..=1024u32 {
            let suffix = if index == 1024 { '1' } else { '0' };
            let name = alloc::format!("symbol{index}{suffix}");
            assert_eq!(sysv_hash(name.as_bytes()) % 2, u32::from(index == 1024));
            offsets.push(u32::try_from(dynstr.len()).unwrap());
            dynstr.extend_from_slice(name.as_bytes());
            dynstr.push(0);
            chains.push(if index >= 1023 {
                0
            } else {
                index.saturating_add(1)
            });
        }
        let table = decoded_symbols(
            &dynstr,
            &offsets,
            None,
            Some(sysv_bytes(&[1, 1024], &chains, ElfData::Little)),
        );
        let missing = b"absent1";
        assert_eq!(sysv_hash(missing) % 2, 1);
        for (name, expected) in [(&missing[..], None), (&b"symbol10241"[..], Some(1024))] {
            NAME_COMPARISONS.store(0, Ordering::Relaxed);
            assert_eq!(table.lookup(name), expected);
            let comparisons = NAME_COMPARISONS.load(Ordering::Relaxed);
            assert!(comparisons > 0 && comparisons <= usize::BITS as usize);
        }
    }
}
