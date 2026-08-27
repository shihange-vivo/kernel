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
use goblin::elf::dynamic::*;

use crate::{
    identity::{read_u32, read_u64},
    DynamicSegmentInfo, ElfClass, Endian, ErrorContext, FileRange, ImageLoadTransaction,
    ImageMemory, LoadError, LoadErrorKind, LoadResult, LoadStage, MappedState, MemoryPermissions,
    ProgramHeaderField, StagedImage, TargetAddr, TargetLocation, TargetRange,
};

const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_RELRENT: u64 = 37;

/// Phase 0's closed-world artifact feature policy.
///
/// Phase 0.5 can supply another `ArtifactFeaturePolicy` to accept dynamic
/// dependencies and TLS without teaching the parser about product policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Phase0ArtifactPolicy;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProgramFeatureSummary {
    pub(crate) interpreter: Option<(u16, FileRange)>,
    pub(crate) tls: Option<(u16, TargetRange)>,
    pub(crate) executable_stack: Option<u16>,
}

impl ProgramFeatureSummary {
    pub const fn interpreter(&self) -> Option<FileRange> {
        match self.interpreter {
            Some((_, range)) => Some(range),
            None => None,
        }
    }

    pub const fn tls(&self) -> Option<TargetRange> {
        match self.tls {
            Some((_, range)) => Some(range),
            None => None,
        }
    }

    pub const fn has_executable_stack(&self) -> bool {
        self.executable_stack.is_some()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DynamicFeatureSummary {
    extended_tag: Option<(u64, u64)>,
    flags: Option<u64>,
    flags_1: Option<u64>,
}

impl DynamicFeatureSummary {
    pub const fn first_extended_tag(&self) -> Option<(u64, u64)> {
        self.extended_tag
    }

    pub const fn flags(&self) -> Option<u64> {
        self.flags
    }

    pub const fn flags_1(&self) -> Option<u64> {
        self.flags_1
    }

    fn observe_extended(&mut self, tag: u64, value: u64) {
        if self.extended_tag.is_none() {
            self.extended_tag = Some((tag, value));
        }
    }
}

pub trait ArtifactFeaturePolicy {
    fn validate_program_features(&self, features: &ProgramFeatureSummary) -> LoadResult<()>;

    fn validate_dynamic_features(&self, features: &DynamicFeatureSummary) -> LoadResult<()>;
}

impl ArtifactFeaturePolicy for Phase0ArtifactPolicy {
    fn validate_program_features(&self, features: &ProgramFeatureSummary) -> LoadResult<()> {
        if let Some((index, range)) = features.interpreter {
            return Err(unsupported_program_header(
                index,
                ProgramHeaderField::UnsupportedInterpreter,
                range.offset(),
            ));
        }
        if let Some((index, range)) = features.tls {
            return Err(unsupported_program_header(
                index,
                ProgramHeaderField::UnsupportedTls,
                range.start().get(),
            ));
        }
        if let Some(index) = features.executable_stack {
            return Err(unsupported_program_header(
                index,
                ProgramHeaderField::ExecutableStack,
                1,
            ));
        }
        Ok(())
    }

    fn validate_dynamic_features(&self, features: &DynamicFeatureSummary) -> LoadResult<()> {
        if let Some((tag, value)) = features.extended_tag {
            return Err(unsupported_dynamic(tag, value));
        }
        if let Some(value) = features.flags.filter(|value| *value & !DF_BIND_NOW != 0) {
            return Err(unsupported_dynamic(DT_FLAGS, value));
        }
        const ALLOWED_FLAGS_1: u64 = DF_1_NOW | DF_1_PIE;
        if let Some(value) = features
            .flags_1
            .filter(|value| *value & !ALLOWED_FLAGS_1 != 0)
        {
            return Err(unsupported_dynamic(DT_FLAGS_1, value));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationAddend {
    Implicit,
    Explicit(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationRecord {
    offset: TargetAddr,
    raw_type: u32,
    symbol_index: u32,
    addend: RelocationAddend,
}

impl RelocationRecord {
    pub const fn offset(&self) -> TargetAddr {
        self.offset
    }

    pub const fn raw_type(&self) -> u32 {
        self.raw_type
    }

    pub const fn symbol_index(&self) -> u32 {
        self.symbol_index
    }

    pub const fn addend(&self) -> RelocationAddend {
        self.addend
    }
}

#[derive(Debug)]
pub struct RuntimeImageMetadata {
    relocations: Box<[RelocationRecord]>,
    features: DynamicFeatureSummary,
}

impl RuntimeImageMetadata {
    pub fn relocations(&self) -> &[RelocationRecord] {
        &self.relocations
    }

    pub const fn features(&self) -> &DynamicFeatureSummary {
        &self.features
    }
}

#[derive(Debug)]
pub struct RuntimeState {
    mapped: MappedState,
    metadata: RuntimeImageMetadata,
}

pub type RuntimeImage<'a, M> = StagedImage<'a, M, RuntimeState>;

impl<'a, M: ImageMemory> StagedImage<'a, M, MappedState> {
    pub fn decode_runtime<P: ArtifactFeaturePolicy + ?Sized>(
        self,
        policy: &P,
    ) -> LoadResult<RuntimeImage<'a, M>> {
        let (mut transaction, mapped) = self.into_parts();
        let runtime = mapped.decode_runtime(&mut transaction, policy)?;
        Ok(StagedImage::new(transaction, runtime))
    }
}

impl RuntimeState {
    pub const fn mapped(&self) -> &MappedState {
        &self.mapped
    }

    pub const fn metadata(&self) -> &RuntimeImageMetadata {
        &self.metadata
    }

    pub(crate) fn into_parts(self) -> (MappedState, RuntimeImageMetadata) {
        (self.mapped, self.metadata)
    }
}

impl MappedState {
    pub(crate) fn decode_runtime<M, P>(
        self,
        transaction: &mut ImageLoadTransaction<'_, M>,
        policy: &P,
    ) -> LoadResult<RuntimeState>
    where
        M: ImageMemory,
        P: ArtifactFeaturePolicy + ?Sized,
    {
        let mut relocations = Vec::new();
        let mut features = DynamicFeatureSummary::default();
        if let Some(dynamic) = self.dynamic() {
            let tags = decode_dynamic_tags(&self, dynamic, transaction.memory())?;
            policy.validate_dynamic_features(&tags.features)?;
            features = tags.features;
            decode_relocation_table(
                &self,
                &tags.rel,
                RelocationTableKind::Rel,
                transaction.memory(),
                &mut relocations,
            )?;
            decode_relocation_table(
                &self,
                &tags.rela,
                RelocationTableKind::Rela,
                transaction.memory(),
                &mut relocations,
            )?;
        }

        Ok(RuntimeState {
            mapped: self,
            metadata: RuntimeImageMetadata {
                relocations: relocations.into_boxed_slice(),
                features,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelocationTableKind {
    Rel,
    Rela,
}

#[derive(Clone, Copy, Debug, Default)]
struct RelocationTableTags {
    address: Option<u64>,
    byte_len: Option<u64>,
    entry_size: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct DynamicTags {
    rel: RelocationTableTags,
    rela: RelocationTableTags,
    features: DynamicFeatureSummary,
}

fn decode_dynamic_tags<M: ImageMemory>(
    mapped: &MappedState,
    dynamic: DynamicSegmentInfo,
    memory: &M,
) -> LoadResult<DynamicTags> {
    let entry_size = dynamic_entry_size(mapped.request().profile().class());
    if dynamic.file_range().is_empty() || dynamic.file_range().len() % entry_size != 0 {
        return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
    }
    if dynamic.file_range().len() > dynamic.memory_size() {
        return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
    }
    let location = locate_file_backed_dynamic(mapped, dynamic)?;
    memory
        .validate_access(
            location,
            dynamic.file_range().len(),
            MemoryPermissions::READ,
        )
        .map_err(|error| error.with_stage(LoadStage::Metadata))?;

    let limits = mapped.request().limits();
    let entry_count = dynamic.file_range().len() / entry_size;
    let mut tags = DynamicTags::default();
    let mut raw = [0; 16];
    let mut terminated = false;
    for index in 0..entry_count {
        limits.check_dynamic_entry_count(index + 1)?;
        let current = location
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                LoadError::new(
                    LoadStage::Metadata,
                    LoadErrorKind::IntegerOverflow,
                    ErrorContext::DynamicTag {
                        tag: DT_NULL,
                        value: index,
                    },
                )
            })?)
            .map_err(|error| error.at(LoadStage::Metadata))?;
        memory
            .read(current, &mut raw[..entry_size as usize])
            .map_err(|error| error.with_stage(LoadStage::Metadata))?;
        let (tag, value) = decode_dynamic_entry(
            &raw[..entry_size as usize],
            mapped.request().profile().class(),
            mapped.request().profile().endian(),
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

fn locate_file_backed_dynamic(
    mapped: &MappedState,
    dynamic: DynamicSegmentInfo,
) -> LoadResult<TargetLocation> {
    for region in mapped.regions() {
        if !region
            .vaddr_range()
            .contains_span(dynamic.vaddr(), dynamic.file_range().len())
            || !region
                .logical_permissions()
                .contains(MemoryPermissions::READ)
        {
            continue;
        }
        let offset = dynamic
            .vaddr()
            .checked_sub(region.vaddr_range().start())
            .map_err(|error| error.at(LoadStage::Metadata))?;
        let expected_file_offset = region
            .file_range()
            .offset()
            .checked_add(offset)
            .ok_or_else(|| dynamic_error(DT_NULL, dynamic.file_range().offset()))?;
        let file_end = offset
            .checked_add(dynamic.file_range().len())
            .filter(|end| *end <= region.file_range().len());
        if expected_file_offset == dynamic.file_range().offset() && file_end.is_some() {
            return mapped.locate_vaddr_at(
                LoadStage::Metadata,
                dynamic.vaddr(),
                dynamic.file_range().len(),
                MemoryPermissions::READ,
            );
        }
    }
    Err(LoadError::new(
        LoadStage::Metadata,
        LoadErrorKind::OutOfBounds,
        ErrorContext::TargetRange {
            start: dynamic.vaddr(),
            len: dynamic.file_range().len(),
        },
    ))
}

fn decode_dynamic_entry(bytes: &[u8], class: ElfClass, endian: Endian) -> LoadResult<(u64, u64)> {
    Ok(match class {
        ElfClass::Elf32 => (
            u64::from(metadata_u32(bytes, 0, endian)?),
            u64::from(metadata_u32(bytes, 4, endian)?),
        ),
        ElfClass::Elf64 => (
            metadata_u64(bytes, 0, endian)?,
            metadata_u64(bytes, 8, endian)?,
        ),
    })
}

fn metadata_u32(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u32> {
    read_u32(bytes, offset, endian).map_err(|error| error.at(LoadStage::Metadata))
}

fn metadata_u64(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u64> {
    read_u64(bytes, offset, endian).map_err(|error| error.at(LoadStage::Metadata))
}

fn accept_dynamic_tag(tags: &mut DynamicTags, tag: u64, value: u64) -> LoadResult<()> {
    match tag {
        DT_REL => set_once(&mut tags.rel.address, tag, value),
        DT_RELSZ => set_once(&mut tags.rel.byte_len, tag, value),
        DT_RELENT => set_once(&mut tags.rel.entry_size, tag, value),
        DT_RELA => set_once(&mut tags.rela.address, tag, value),
        DT_RELASZ => set_once(&mut tags.rela.byte_len, tag, value),
        DT_RELAENT => set_once(&mut tags.rela.entry_size, tag, value),
        DT_RELR | DT_RELRSZ | DT_RELRENT | DT_NEEDED | DT_PLTRELSZ | DT_PLTREL | DT_TEXTREL
        | DT_JMPREL | DT_INIT | DT_FINI | DT_SONAME | DT_RPATH | DT_SYMBOLIC | DT_INIT_ARRAY
        | DT_FINI_ARRAY | DT_INIT_ARRAYSZ | DT_FINI_ARRAYSZ | DT_RUNPATH | DT_PREINIT_ARRAY
        | DT_PREINIT_ARRAYSZ | DT_VERSYM | DT_VERDEF | DT_VERDEFNUM | DT_VERNEED
        | DT_VERNEEDNUM | DT_TLSDESC_PLT | DT_TLSDESC_GOT => {
            tags.features.observe_extended(tag, value);
            Ok(())
        }
        DT_FLAGS => set_once(&mut tags.features.flags, tag, value),
        DT_FLAGS_1 => set_once(&mut tags.features.flags_1, tag, value),
        DT_PLTGOT | DT_HASH | DT_STRTAB | DT_SYMTAB | DT_STRSZ | DT_SYMENT | DT_DEBUG
        | DT_BIND_NOW | DT_GNU_HASH | DT_RELACOUNT | DT_RELCOUNT => Ok(()),
        _ => {
            tags.features.observe_extended(tag, value);
            Ok(())
        }
    }
}

fn set_once(slot: &mut Option<u64>, tag: u64, value: u64) -> LoadResult<()> {
    if slot.replace(value).is_some() {
        Err(dynamic_error(tag, value))
    } else {
        Ok(())
    }
}

fn decode_relocation_table<M: ImageMemory>(
    mapped: &MappedState,
    tags: &RelocationTableTags,
    kind: RelocationTableKind,
    memory: &M,
    records: &mut Vec<RelocationRecord>,
) -> LoadResult<()> {
    let absent = tags.address.is_none() && tags.byte_len.is_none() && tags.entry_size.is_none();
    if absent {
        return Ok(());
    }
    let tag = match kind {
        RelocationTableKind::Rel => DT_REL,
        RelocationTableKind::Rela => DT_RELA,
    };
    let (Some(address), Some(byte_len), Some(entry_size)) =
        (tags.address, tags.byte_len, tags.entry_size)
    else {
        return Err(dynamic_error(tag, 0));
    };
    let expected_entry_size = relocation_entry_size(mapped.request().profile().class(), kind);
    if entry_size != expected_entry_size || byte_len % entry_size != 0 {
        return Err(dynamic_error(tag, entry_size));
    }
    let count = byte_len / entry_size;
    let total = (records.len() as u64)
        .checked_add(count)
        .ok_or_else(|| dynamic_error(tag, count))?;
    mapped.request().limits().check_relocation_count(total)?;
    let metadata_bytes = total
        .checked_mul(core::mem::size_of::<RelocationRecord>() as u64)
        .unwrap_or(u64::MAX);
    mapped
        .request()
        .limits()
        .check_runtime_metadata_bytes(metadata_bytes)?;
    let count_usize = usize::try_from(count).map_err(|_| dynamic_error(tag, count))?;
    records.try_reserve_exact(count_usize).map_err(|_| {
        LoadError::new(
            LoadStage::Metadata,
            LoadErrorKind::OutOfMemory,
            ErrorContext::DynamicTag { tag, value: count },
        )
    })?;
    if byte_len == 0 {
        return Ok(());
    }

    let table_vaddr = TargetAddr::new(address);
    let location = mapped.locate_vaddr_at(
        LoadStage::Metadata,
        table_vaddr,
        byte_len,
        MemoryPermissions::READ,
    )?;
    memory
        .validate_access(location, byte_len, MemoryPermissions::READ)
        .map_err(|error| error.with_stage(LoadStage::Metadata))?;
    let mut raw = [0; 24];
    for index in 0..count {
        let entry_location = location
            .checked_add(index * entry_size)
            .map_err(|error| error.at(LoadStage::Metadata))?;
        memory
            .read(entry_location, &mut raw[..entry_size as usize])
            .map_err(|error| error.with_stage(LoadStage::Metadata))?;
        let record = decode_relocation_entry(
            &raw[..entry_size as usize],
            mapped.request().profile().class(),
            mapped.request().profile().endian(),
            kind,
        )?;
        if record.symbol_index != 0 {
            return Err(unsupported_relocation(record));
        }
        records.push(record);
    }
    Ok(())
}

fn decode_relocation_entry(
    bytes: &[u8],
    class: ElfClass,
    endian: Endian,
    kind: RelocationTableKind,
) -> LoadResult<RelocationRecord> {
    let (offset, info, addend) = match (class, kind) {
        (ElfClass::Elf32, RelocationTableKind::Rel) => (
            u64::from(metadata_u32(bytes, 0, endian)?),
            u64::from(metadata_u32(bytes, 4, endian)?),
            RelocationAddend::Implicit,
        ),
        (ElfClass::Elf32, RelocationTableKind::Rela) => (
            u64::from(metadata_u32(bytes, 0, endian)?),
            u64::from(metadata_u32(bytes, 4, endian)?),
            RelocationAddend::Explicit(i64::from(metadata_u32(bytes, 8, endian)? as i32)),
        ),
        (ElfClass::Elf64, RelocationTableKind::Rel) => (
            metadata_u64(bytes, 0, endian)?,
            metadata_u64(bytes, 8, endian)?,
            RelocationAddend::Implicit,
        ),
        (ElfClass::Elf64, RelocationTableKind::Rela) => (
            metadata_u64(bytes, 0, endian)?,
            metadata_u64(bytes, 8, endian)?,
            RelocationAddend::Explicit(metadata_u64(bytes, 16, endian)? as i64),
        ),
    };
    let (raw_type, symbol_index) = match class {
        ElfClass::Elf32 => ((info & 0xff) as u32, (info >> 8) as u32),
        ElfClass::Elf64 => (info as u32, (info >> 32) as u32),
    };
    Ok(RelocationRecord {
        offset: TargetAddr::new(offset),
        raw_type,
        symbol_index,
        addend,
    })
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

fn dynamic_error(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Metadata,
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag { tag, value },
    )
}

fn unsupported_dynamic(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Metadata,
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::DynamicTag { tag, value },
    )
}

fn unsupported_program_header(index: u16, field: ProgramHeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Plan,
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
        LoadStage::Metadata,
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::Relocation {
            offset: record.offset,
            raw_type: record.raw_type,
            symbol_index: record.symbol_index,
        },
    )
}
