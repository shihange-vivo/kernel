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

//! Bounded PT_DYNAMIC parsing and validation of referenced ELF tables.
//! Addresses remain ELF virtual addresses; this module does not relocate memory.

use alloc::vec::Vec;
use goblin::elf::dynamic::{
    DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS,
    DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED,
    DT_NULL, DT_PLTREL, DT_PLTRELSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_REL, DT_RELA,
    DT_RELAENT, DT_RELASZ, DT_RELENT, DT_RELSZ, DT_SONAME, DT_STRSZ, DT_STRTAB, DT_SYMENT,
    DT_SYMTAB,
};

#[cfg(any(test, enable_dynamic_linker))]
use super::{
    hash::{GnuHash, SysvHash},
    segment::vaddr_file_extent,
    symbol::SymbolTableReader,
    ElfData,
};
use super::{
    read_u32, read_u64,
    relocation::{RelocationFormat, RelocationTable},
    segment::vaddr_to_file_range,
    strings::string_range,
    symbol_entry_size, ElfClass, ElfHeaderInfo, FileRange, LoadSegmentInfo, ProgramHeaderInfo,
    GNU_HASH_HEADER_SIZE, SYSV_HASH_HEADER_SIZE,
};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::{TargetAddress, TargetRange},
    ElfReader, LoadError, LoadResult,
};

#[derive(Debug)]
struct DynamicEntry {
    tag: u64,
    value: u64,
}

pub(crate) const LIFECYCLE_ARRAYS: [(u64, u64); 3] = [
    (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
    (DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
    (DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
];

/// Validated raw metadata; symbol and dependency decoding follow later.
/// Tag addresses remain in the ELF virtual address space, not runtime addresses.
#[derive(Debug)]
pub(crate) struct DynamicInfo {
    entries: Vec<DynamicEntry>,
    tables: [Option<RelocationTable>; 3],
}

impl DynamicInfo {
    pub(crate) fn value(&self, tag: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }

    /// Preserve DT_NEEDED encounter order; values are dynstr offsets, not names.
    pub(crate) fn needed(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.tag == DT_NEEDED)
            .map(|entry| entry.value)
    }

    /// File backing for a nonempty DT_STRTAB/DT_STRSZ pair.
    pub(crate) fn string_file_range(
        &self,
        segments: &[LoadSegmentInfo],
    ) -> LoadResult<Option<FileRange>> {
        match (self.value(DT_STRTAB), self.value(DT_STRSZ)) {
            (None, None) | (Some(_), Some(0)) => Ok(None),
            (Some(address), Some(len)) => {
                vaddr_to_file_range(segments, TargetAddress::new(address), len)
                    .map(Some)
                    .ok_or_else(|| dynamic_error(DT_STRTAB, address))
            }
            _ => Err(dynamic_error(DT_STRTAB, 0)),
        }
    }

    /// Open the dynamic symbol table using a count established from its hash metadata.
    #[cfg(any(test, enable_dynamic_linker))]
    pub(crate) fn symbol_table<'a, R: ElfReader>(
        &self,
        reader: &'a R,
        segments: &[LoadSegmentInfo],
        class: ElfClass,
        endian: ElfData,
    ) -> LoadResult<Option<SymbolTableReader<'a, R>>> {
        let sysv = self
            .value(DT_HASH)
            .map(|address| SysvHash::read(reader, segments, TargetAddress::new(address), endian))
            .transpose()?;
        let sysv_count = sysv.as_ref().map(SysvHash::count);
        let (gnu, count) = match self.value(DT_GNU_HASH) {
            Some(address) => {
                let (hash, count) =
                    self.read_gnu_hash(reader, segments, address, class, endian, sysv_count)?;
                (Some(hash), Some(count))
            }
            None => (None, sysv_count),
        };
        let Some(count) = count else {
            return Ok(None);
        };
        let file = self
            .symbol_file_range(segments, class, count)?
            .ok_or_else(|| dynamic_error(DT_SYMTAB, 0))?;
        Ok(Some(SymbolTableReader::new(
            reader,
            file,
            count,
            class,
            endian,
            self.string_file_range(segments)?,
            sysv,
            gnu,
        )))
    }

    #[cfg(any(test, enable_dynamic_linker))]
    fn read_gnu_hash(
        &self,
        reader: &impl ElfReader,
        segments: &[LoadSegmentInfo],
        address: u64,
        class: ElfClass,
        endian: ElfData,
        sysv_count: Option<u32>,
    ) -> LoadResult<(GnuHash, u32)> {
        let symbol_address = self
            .value(DT_SYMTAB)
            .ok_or_else(|| dynamic_error(DT_SYMTAB, 0))?;
        let symbols = self
            .symbol_metadata_file_extent(segments, symbol_address)
            .ok_or_else(|| dynamic_error(DT_SYMTAB, symbol_address))?;
        let capacity = symbols.len() / symbol_entry_size(class);
        if capacity == 0 || sysv_count.is_some_and(|count| u64::from(count) > capacity) {
            return Err(dynamic_error(DT_SYMTAB, symbol_address));
        }
        let max_symbols = sysv_count.unwrap_or_else(|| u32::try_from(capacity).unwrap_or(u32::MAX));
        let hash = self
            .symbol_metadata_file_extent(segments, address)
            .ok_or_else(|| dynamic_error(DT_GNU_HASH, address))?;
        let (hash, gnu_count) = GnuHash::read(
            reader,
            hash,
            TargetAddress::new(address),
            class,
            endian,
            max_symbols,
        )?;
        if let Some(count) = gnu_count {
            if sysv_count.is_some_and(|expected| count != expected) {
                return Err(dynamic_error(DT_GNU_HASH, address));
            }
            return Ok((hash, count));
        }
        // An empty GNU hash can leave unindexed symbols in .dynsym.
        let count = sysv_count.ok_or_else(|| {
            LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::DynamicTag {
                    tag: DT_GNU_HASH,
                    value: address,
                },
            )
        })?;
        Ok((hash, count))
    }

    /// Limit an inferred table extent at the next known symbol-related table.
    #[cfg(any(test, enable_dynamic_linker))]
    fn symbol_metadata_file_extent(
        &self,
        segments: &[LoadSegmentInfo],
        address: u64,
    ) -> Option<FileRange> {
        let file = vaddr_file_extent(segments, TargetAddress::new(address))?;
        let strings = self
            .value(DT_STRTAB)
            .filter(|_| self.value(DT_STRSZ).is_some_and(|len| len != 0));
        let len = [
            self.value(DT_SYMTAB),
            self.value(DT_HASH),
            self.value(DT_GNU_HASH),
            strings,
        ]
        .into_iter()
        .flatten()
        .filter_map(|next| next.checked_sub(address).filter(|&len| len != 0))
        .fold(file.len(), u64::min);
        Some(FileRange::new(file.offset(), len))
    }

    fn symbol_file_range(
        &self,
        segments: &[LoadSegmentInfo],
        class: ElfClass,
        count: u32,
    ) -> LoadResult<Option<FileRange>> {
        match (self.value(DT_SYMTAB), self.value(DT_SYMENT)) {
            (None, None) => Ok(None),
            (Some(address), Some(size)) => {
                if size != symbol_entry_size(class) {
                    return Err(dynamic_error(DT_SYMENT, size));
                }
                vaddr_to_file_range(
                    segments,
                    TargetAddress::new(address),
                    u64::from(count) * size,
                )
                .map(Some)
                .ok_or_else(|| dynamic_error(DT_SYMTAB, address))
            }
            _ => Err(dynamic_error(DT_SYMTAB, 0)),
        }
    }

    pub(crate) fn is_pie(&self) -> bool {
        self.value(DT_FLAGS_1).unwrap_or(0) & DF_1_PIE != 0
    }

    /// Whether any dynamic entry explicitly requests immediate binding.
    pub(crate) fn bind_now(&self) -> bool {
        self.value(DT_BIND_NOW).is_some()
            || self.value(DT_FLAGS).unwrap_or(0) & DF_BIND_NOW != 0
            || self.value(DT_FLAGS_1).unwrap_or(0) & DF_1_NOW != 0
    }

    pub(crate) fn relocation_tables(&self) -> impl Iterator<Item = &RelocationTable> {
        self.tables.iter().flatten()
    }

    /// Count ELF records across the normalized relocation tables for one image.
    pub(crate) fn relocation_count(&self, class: ElfClass) -> LoadResult<u64> {
        self.relocation_tables().try_fold(0u64, |total, table| {
            let range = table.range();
            let count = range.len() / table.format().entry_size(class);
            total
                .checked_add(count)
                .ok_or_else(|| dynamic_range_error(range.start(), range.len()))
        })
    }

    /// Array geometry is validated before allocation; pointers are read after relocation.
    pub(crate) fn lifecycle_arrays(&self) -> impl Iterator<Item = (u64, TargetRange)> + '_ {
        LIFECYCLE_ARRAYS.into_iter().filter_map(|(tag, size_tag)| {
            Some((
                tag,
                TargetRange::new(TargetAddress::new(self.value(tag)?), self.value(size_tag)?),
            ))
        })
    }
}

/// Read PT_DYNAMIC and check its file-backed tables. The caller supplies entry
/// budgets and tag admission rules.
pub(crate) fn read_dynamic(
    reader: &impl ElfReader,
    header: &ProgramHeaderInfo,
    segments: &[LoadSegmentInfo],
    elf_header: &ElfHeaderInfo,
    check_entry_count: impl Fn(u64) -> LoadResult<()>,
    mut check_tag: impl FnMut(u64, u64) -> LoadResult<()>,
) -> LoadResult<DynamicInfo> {
    let class = elf_header.class();
    let endian = elf_header.endian();
    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    let bytes = header.file_size();
    if bytes == 0 || !bytes.is_multiple_of(entry_size) || bytes > header.memory_size() {
        return Err(dynamic_range_error(header.vaddr(), bytes));
    }
    // A dynamic table must describe the same file bytes as its load segment,
    // rather than pointing to BSS or an unrelated file-to-VA mapping.
    let file = vaddr_to_file_range(segments, header.vaddr(), bytes)
        .ok_or_else(|| dynamic_range_error(header.vaddr(), bytes))?;
    if file.offset() != header.file_offset()
        || !segments.iter().any(|segment| {
            TargetRange::new(segment.vaddr(), segment.memory_size())
                .contains_span(header.vaddr(), header.memory_size())
        })
    {
        return Err(dynamic_range_error(header.vaddr(), bytes));
    }
    let mut info = DynamicInfo {
        entries: Vec::new(),
        tables: [None; 3],
    };
    let mut raw = [0; 16];
    let mut terminated = false;
    for index in 0..bytes / entry_size {
        // Check before reading or reserving: padding must not drive allocation.
        check_entry_count(index + 1)?;
        let offset = index
            .checked_mul(entry_size)
            .and_then(|n| file.offset().checked_add(n))
            .ok_or_else(|| dynamic_range_error(header.vaddr(), bytes))?;
        reader.read_exact_at(offset, &mut raw[..entry_size as usize])?;
        let (tag, value) = match class {
            ElfClass::Elf32 => (
                u64::from(read_u32(&raw, 0, endian)?),
                u64::from(read_u32(&raw, 4, endian)?),
            ),
            ElfClass::Elf64 => (read_u64(&raw, 0, endian)?, read_u64(&raw, 8, endian)?),
        };
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        check_tag(tag, value)?;
        info.entries.try_reserve(1).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag { tag, value },
            )
        })?;
        info.entries.push(DynamicEntry { tag, value });
    }
    if !terminated {
        return Err(dynamic_error(DT_NULL, bytes));
    }
    validate_file_metadata(&info, segments, class)?;
    info.tables = relocation_tables(&info, segments, class)?;
    Ok(info)
}

fn validate_file_metadata(
    info: &DynamicInfo,
    segments: &[LoadSegmentInfo],
    class: ElfClass,
) -> LoadResult<()> {
    let strings = info.string_file_range(segments)?;
    for offset in info.needed().chain(info.value(DT_SONAME)) {
        if strings
            .and_then(|table| string_range(table, offset))
            .is_none()
        {
            return Err(dynamic_error(DT_STRTAB, offset));
        }
    }
    // The standalone path only needs the minimum geometry. Counted access is opt-in.
    info.symbol_file_range(segments, class, 1)?;
    for (tag, len) in [
        (DT_HASH, SYSV_HASH_HEADER_SIZE),
        (DT_GNU_HASH, GNU_HASH_HEADER_SIZE),
    ] {
        if let Some(address) = info.value(tag) {
            vaddr_to_file_range(segments, TargetAddress::new(address), len)
                .ok_or_else(|| dynamic_error(tag, address))?;
        }
    }
    Ok(())
}

fn table(
    segments: &[LoadSegmentInfo],
    address: Option<u64>,
    len: Option<u64>,
    entry_size: Option<u64>,
    format: RelocationFormat,
    class: ElfClass,
    tag: u64,
) -> LoadResult<Option<RelocationTable>> {
    match (address, len, entry_size) {
        (None, None, None) => Ok(None),
        (Some(address), Some(len), Some(size)) => {
            if size != format.entry_size(class) || !len.is_multiple_of(size) {
                return Err(dynamic_error(tag, size));
            }
            let range = TargetRange::new(TargetAddress::new(address), len);
            range.end()?;
            // Validate the original table before overlap normalization loses
            // its source tag and starting address.
            if len != 0 {
                vaddr_to_file_range(segments, range.start(), len)
                    .ok_or_else(|| dynamic_error(tag, address))?;
            }
            Ok(Some(RelocationTable::new(range, format)))
        }
        _ => Err(dynamic_error(tag, 0)),
    }
}

fn relocation_tables(
    info: &DynamicInfo,
    segments: &[LoadSegmentInfo],
    class: ElfClass,
) -> LoadResult<[Option<RelocationTable>; 3]> {
    let rel = table(
        segments,
        info.value(DT_REL),
        info.value(DT_RELSZ),
        info.value(DT_RELENT),
        RelocationFormat::Rel,
        class,
        DT_REL,
    )?;
    let rela = table(
        segments,
        info.value(DT_RELA),
        info.value(DT_RELASZ),
        info.value(DT_RELAENT),
        RelocationFormat::Rela,
        class,
        DT_RELA,
    )?;
    let plt = match (
        info.value(DT_JMPREL),
        info.value(DT_PLTRELSZ),
        info.value(DT_PLTREL),
    ) {
        (None, None, None) => None,
        (Some(address), Some(len), Some(format)) if format == DT_REL || format == DT_RELA => {
            let format = if format == DT_REL {
                RelocationFormat::Rel
            } else {
                RelocationFormat::Rela
            };
            table(
                segments,
                Some(address),
                Some(len),
                Some(format.entry_size(class)),
                format,
                class,
                DT_JMPREL,
            )?
        }
        _ => return Err(dynamic_error(DT_JMPREL, 0)),
    };
    let mut tables = [rel, rela, plt];
    // JMPREL may overlap the main table. Merge aligned, same-format ranges so
    // later eager relocation never applies the same table entry twice.
    for (i, tag) in [DT_REL, DT_RELA, DT_JMPREL].into_iter().enumerate() {
        let Some(current) = tables[i] else {
            continue;
        };
        let mut merged = false;
        let range = current.range();
        let format = current.format();
        for previous in tables[..i].iter_mut().flatten() {
            let previous_range = previous.range();
            if !range.overlaps(previous_range) {
                continue;
            }
            let start = range.start().min(previous_range.start());
            let displacement = range.start().get().abs_diff(previous_range.start().get());
            if format != previous.format() || !displacement.is_multiple_of(format.entry_size(class))
            {
                return Err(dynamic_error(tag, range.start().get()));
            }
            let end = range.end()?.max(previous_range.end()?);
            *previous =
                RelocationTable::new(TargetRange::new(start, end.checked_sub(start)?), format);
            merged = true;
            break;
        }
        if merged {
            tables[i] = None;
        }
    }
    Ok(tables)
}

fn dynamic_range_error(start: TargetAddress, len: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::TargetRange {
            start,
            len,
            align: 1,
        },
    )
}

fn dynamic_error(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag { tag, value },
    )
}
