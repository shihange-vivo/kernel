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
use goblin::elf::dynamic::{
    DF_TEXTREL, DT_BIND_NOW, DT_DEBUG, DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS,
    DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL,
    DT_NEEDED, DT_NULL, DT_PLTGOT, DT_PLTREL, DT_PLTRELSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ,
    DT_REL, DT_RELA, DT_RELACOUNT, DT_RELAENT, DT_RELASZ, DT_RELCOUNT, DT_RELENT, DT_RELSZ,
    DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_STRTAB, DT_SYMBOLIC, DT_SYMENT, DT_SYMTAB,
    DT_TEXTREL, DT_TLSDESC_GOT, DT_TLSDESC_PLT, DT_VERDEF, DT_VERDEFNUM, DT_VERNEED, DT_VERNEEDNUM,
    DT_VERSYM,
};

use crate::{
    address::{FileRange, TargetAddress, TargetRange},
    elf::{DynamicSegmentInfo, LoadSegmentInfo, DT_RELR, DT_RELRENT, DT_RELRSZ},
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage, ProgramHeaderField},
    identity::{ElfClass, ElfData, LoadRequest},
    image::{
        decode::{
            DecodedImage, DynamicTags, RelocationAddend, RelocationRecord, RelocationTableKind,
            RelocationTableTags,
        },
        inspect::StackKind,
        read_u32, read_u64,
    },
    memory::{AllocationOffset, ImageMemory},
    reader::ElfReader,
};

pub(crate) struct LoadedRegion {
    vaddr_range: TargetRange,
    runtime_range: TargetRange,
    file_range: FileRange,
    allocation_offset: AllocationOffset,
}

impl LoadedRegion {
    #[inline]
    pub const fn new(
        vaddr_range: TargetRange,
        runtime_range: TargetRange,
        file_range: FileRange,
        allocation_offset: AllocationOffset,
    ) -> Self {
        Self {
            vaddr_range,
            runtime_range,
            file_range,
            allocation_offset,
        }
    }

    #[inline]
    pub const fn vaddr_range(&self) -> TargetRange {
        self.vaddr_range
    }

    #[inline]
    pub const fn runtime_range(&self) -> TargetRange {
        self.runtime_range
    }

    #[inline]
    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    #[inline]
    pub const fn allocation_offset(&self) -> AllocationOffset {
        self.allocation_offset
    }
}

pub(crate) struct MappedImage<R: ElfReader, M: ImageMemory> {
    reader: R,
    memory: M,
    load_bias: TargetAddress,
    request: LoadRequest,
    entry_vaddr: TargetAddress,
    canonical_entry_vaddr: TargetAddress,
    load_segments: Box<[LoadSegmentInfo]>,
    regions: Vec<LoadedRegion>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack: StackKind,
    interpreter: Option<FileRange>,
    tls: Option<TargetRange>,
}

impl<R: ElfReader, M: ImageMemory> MappedImage<R, M> {
    #[inline]
    pub fn new(
        reader: R,
        memory: M,
        load_bias: TargetAddress,
        request: LoadRequest,
        entry_vaddr: TargetAddress,
        canonical_entry_vaddr: TargetAddress,
        load_segments: Box<[LoadSegmentInfo]>,
        regions: Vec<LoadedRegion>,
        dynamic: Option<DynamicSegmentInfo>,
        relro: Option<TargetRange>,
        stack: StackKind,
        interpreter: Option<FileRange>,
        tls: Option<TargetRange>,
    ) -> Self {
        Self {
            reader,
            memory,
            load_bias,
            request,
            entry_vaddr,
            canonical_entry_vaddr,
            load_segments,
            regions,
            dynamic,
            relro,
            stack,
            interpreter,
            tls,
        }
    }

    fn locate_vaddr_at(&self, vaddr: TargetAddress, len: u64) -> LoadResult<AllocationOffset> {
        let region = self
            .regions
            .iter()
            .find(|region| region.vaddr_range().contains_span(vaddr, len))
            .ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange {
                        start: vaddr,
                        len,
                        align: 0,
                    },
                )
            })?;
        let offset = vaddr.checked_sub(region.vaddr_range().start())?;
        region.allocation_offset().checked_add(offset)
    }

    fn locate_file_backed_dynamic(
        &self,
        dynamic: &DynamicSegmentInfo,
    ) -> LoadResult<AllocationOffset> {
        for region in self.regions.iter() {
            if !region
                .vaddr_range()
                .contains_span(dynamic.vaddr(), dynamic.file_range().len())
            {
                continue;
            }
            let offset = dynamic.vaddr().checked_sub(region.vaddr_range().start())?;
            let expected_file_offset = region
                .file_range()
                .offset()
                .checked_add(offset)
                .ok_or_else(|| dynamic_error(DT_NULL, dynamic.file_range().offset()))?;
            let file_end = offset
                .checked_add(dynamic.file_range().len())
                .filter(|end| *end <= region.file_range().len());
            if expected_file_offset == dynamic.file_range().offset() {
                return self.locate_vaddr_at(dynamic.vaddr(), dynamic.file_range().len());
            }
        }
        Err(LoadError::new(
            LoadErrorKind::OutOfBounds,
            ErrorContext::TargetRange {
                start: dynamic.vaddr(),
                len: dynamic.file_range().len(),
                align: 0,
            },
        ))
    }

    fn decode_dynamic_tags(&self) -> LoadResult<DynamicTags> {
        let dynamic = self.dynamic.as_ref().unwrap();
        let entry_size = dynamic_entry_size(self.request.profile().class());

        if dynamic.file_range().is_empty() || dynamic.file_range().len() % entry_size != 0 {
            return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
        }
        if dynamic.file_range().len() > dynamic.memory_size() {
            return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
        }
        let offset = self.locate_file_backed_dynamic(dynamic)?;
        self.memory.image_span(offset, dynamic.file_range().len())?;

        let limits = self.request.limits();
        let entry_count = dynamic.file_range().len() / entry_size;
        let mut tags = DynamicTags::default();
        let mut raw = [0; 16];
        let mut terminated = false;
        for index in 0..entry_count {
            limits.check_dynamic_entry_count(index + 1)?;
            let current =
                offset.checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                    LoadError::new(
                        LoadErrorKind::IntegerOverflow,
                        ErrorContext::DynamicTag {
                            tag: DT_NULL,
                            value: index,
                        },
                    )
                })?)?;
            self.memory.read(current, &mut raw[..entry_size as usize])?;
            let (tag, value) = decode_dynamic_entry(
                &raw[..entry_size as usize],
                self.request.profile().class(),
                self.request.profile().endian(),
            )?;
            if tag == DT_NULL {
                terminated = true;
                break;
            }
            accept_dynamic_tag(&mut tags, tag, value)?;
        }
        if !terminated {
            return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
        }
        Ok(tags)
    }

    fn decode_relocation_table(
        &self,
        tags: &RelocationTableTags,
        kind: RelocationTableKind,
        records: &mut Vec<RelocationRecord>,
    ) -> LoadResult<()> {
        let absent =
            tags.address().is_none() && tags.byte_len().is_none() && tags.entry_size().is_none();
        if absent {
            return Ok(());
        }
        let tag = match kind {
            RelocationTableKind::Rel => DT_REL,
            RelocationTableKind::Rela => DT_RELA,
        };
        let (Some(address), Some(byte_len), Some(entry_size)) =
            (tags.address(), tags.byte_len(), tags.entry_size())
        else {
            return Err(dynamic_error(tag, 0));
        };
        let expected_entry_size = relocation_entry_size(self.request.profile().class(), kind);
        if entry_size != expected_entry_size || byte_len % entry_size != 0 {
            return Err(dynamic_error(tag, entry_size));
        }
        let count = byte_len / entry_size;
        let existing = u64::try_from(records.len()).map_err(|_| dynamic_error(tag, count))?;
        let total = existing
            .checked_add(count)
            .ok_or_else(|| dynamic_error(tag, count))?;
        self.request.limits().check_relocation_count(total)?;
        let count_usize = usize::try_from(count).map_err(|_| dynamic_error(tag, count))?;
        records.try_reserve_exact(count_usize).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag { tag, value: count },
            )
        })?;
        if byte_len == 0 {
            return Ok(());
        }
        let table_vaddr = TargetAddress::new(address);
        let offset = self.locate_vaddr_at(table_vaddr, byte_len)?;
        self.memory.image_span(offset, byte_len)?;
        let mut raw = [0; 24];
        for index in 0..count {
            let entry_offset = offset.checked_add(index * entry_size)?;
            self.memory
                .read(entry_offset, &mut raw[..entry_size as usize])?;
            let record = decode_relocation_entry(
                &raw[..entry_size as usize],
                self.request.profile().class(),
                self.request.profile().endian(),
                kind,
            )?;
            if record.symbol_index() != 0 {
                return Err(unsupported_relocation(record));
            }
            records.push(record);
        }
        Ok(())
    }

    pub fn decode(mut self) -> LoadResult<DecodedImage<R, M>> {
        let mut relocations = Vec::new();
        if let Some(dynamic) = self.dynamic.as_ref() {
            let tags = self
                .decode_dynamic_tags()
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            self.decode_relocation_table(tags.rel(), RelocationTableKind::Rel, &mut relocations)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            self.decode_relocation_table(tags.rela(), RelocationTableKind::Rela, &mut relocations)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
        }

        Ok(DecodedImage::new(
            self.reader,
            self.memory,
            self.load_bias,
            self.request,
            self.entry_vaddr,
            self.canonical_entry_vaddr,
            self.load_segments,
            self.regions,
            self.dynamic,
            relocations,
            self.relro,
            self.stack,
            self.interpreter,
            self.tls,
        ))
    }
}

const fn dynamic_entry_size(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    }
}

const fn relocation_entry_size(class: ElfClass, kind: RelocationTableKind) -> u64 {
    match (class, kind) {
        (ElfClass::Elf32, RelocationTableKind::Rel) => 8,
        (ElfClass::Elf32, RelocationTableKind::Rela) => 12,
        (ElfClass::Elf64, RelocationTableKind::Rel) => 16,
        (ElfClass::Elf64, RelocationTableKind::Rela) => 24,
    }
}

fn decode_dynamic_entry(bytes: &[u8], class: ElfClass, endian: ElfData) -> LoadResult<(u64, u64)> {
    Ok(match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(bytes, 0, endian)?),
            u64::from(read_u32(bytes, 4, endian)?),
        ),
        ElfClass::Elf64 => (read_u64(bytes, 0, endian)?, read_u64(bytes, 8, endian)?),
    })
}

fn set_once(slot: &mut Option<u64>, tag: u64, value: u64) -> LoadResult<()> {
    if slot.replace(value).is_some() {
        Err(dynamic_error(tag, value))
    } else {
        Ok(())
    }
}

fn decode_relocation_entry(
    bytes: &[u8],
    class: ElfClass,
    endian: ElfData,
    kind: RelocationTableKind,
) -> LoadResult<RelocationRecord> {
    let (offset, info, addend) = match (class, kind) {
        (ElfClass::Elf32, RelocationTableKind::Rel) => (
            u64::from(read_u32(bytes, 0, endian)?),
            u64::from(read_u32(bytes, 4, endian)?),
            RelocationAddend::Implicit,
        ),
        (ElfClass::Elf32, RelocationTableKind::Rela) => (
            u64::from(read_u32(bytes, 0, endian)?),
            u64::from(read_u32(bytes, 4, endian)?),
            RelocationAddend::Explicit(i64::from(read_u32(bytes, 8, endian)? as i32)),
        ),
        (ElfClass::Elf64, RelocationTableKind::Rel) => (
            read_u64(bytes, 0, endian)?,
            read_u64(bytes, 8, endian)?,
            RelocationAddend::Implicit,
        ),
        (ElfClass::Elf64, RelocationTableKind::Rela) => (
            read_u64(bytes, 0, endian)?,
            read_u64(bytes, 8, endian)?,
            RelocationAddend::Explicit(read_u64(bytes, 16, endian)? as i64),
        ),
    };
    let (raw_type, symbol_index) = match class {
        ElfClass::Elf32 => ((info & 0xff) as u32, (info >> 8) as u32),
        ElfClass::Elf64 => (info as u32, (info >> 32) as u32),
    };
    Ok(RelocationRecord::new(
        TargetAddress::new(offset),
        raw_type,
        symbol_index,
        addend,
    ))
}

fn accept_dynamic_tag(tags: &mut DynamicTags, tag: u64, value: u64) -> LoadResult<()> {
    match tag {
        DT_REL => set_once(tags.rel_mut().address_mut(), tag, value),
        DT_RELSZ => set_once(tags.rel_mut().byte_len_mut(), tag, value),
        DT_RELENT => set_once(tags.rel_mut().entry_size_mut(), tag, value),
        DT_RELA => set_once(tags.rela_mut().address_mut(), tag, value),
        DT_RELASZ => set_once(tags.rela_mut().byte_len_mut(), tag, value),
        DT_RELAENT => set_once(tags.rela_mut().entry_size_mut(), tag, value),
        DT_TEXTREL => Err(unsupported_dynamic(tag, value)),
        DT_RELR | DT_RELRSZ | DT_RELRENT | DT_NEEDED | DT_PLTRELSZ | DT_PLTREL | DT_JMPREL
        | DT_INIT | DT_FINI | DT_SONAME | DT_RPATH | DT_SYMBOLIC | DT_INIT_ARRAY
        | DT_FINI_ARRAY | DT_INIT_ARRAYSZ | DT_FINI_ARRAYSZ | DT_RUNPATH | DT_PREINIT_ARRAY
        | DT_PREINIT_ARRAYSZ | DT_VERSYM | DT_VERDEF | DT_VERDEFNUM | DT_VERNEED
        | DT_VERNEEDNUM | DT_TLSDESC_PLT | DT_TLSDESC_GOT => Ok(()),
        DT_FLAGS if value & DF_TEXTREL != 0 => Err(unsupported_dynamic(tag, value)),
        DT_FLAGS => Ok(()),
        DT_FLAGS_1 => Ok(()),
        DT_PLTGOT | DT_HASH | DT_STRTAB | DT_SYMTAB | DT_STRSZ | DT_SYMENT | DT_DEBUG
        | DT_BIND_NOW | DT_GNU_HASH | DT_RELACOUNT | DT_RELCOUNT => Ok(()),
        _ => Ok(()),
    }
}

fn dynamic_error(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag { tag, value },
    )
}

fn unsupported_dynamic(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::DynamicTag { tag, value },
    )
}

fn unsupported_program_header(index: u16, field: ProgramHeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::ProgramHeader {
            index,
            field,
            value,
        },
    )
}

fn unsupported_relocation(record: RelocationRecord) -> LoadError {
    LoadError::new(
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::Relocation {
            offset: record.offset(),
            raw_type: record.raw_type(),
            symbol_index: record.symbol_index(),
        },
    )
}
