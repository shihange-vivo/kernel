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

use alloc::vec::Vec;
use goblin::elf::program_header::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_TLS,
};

use crate::{
    identity::{read_u32, read_u64},
    AdmittedArtifact, ElfClass, ElfReader, Endian, ErrorContext, FileRange, ImageLoader, LoadError,
    LoadErrorKind, LoadResult, LoadStage, MemoryPermissions, ProgramHeaderField, TargetAddr,
    TargetRange,
};

use super::metadata::ProgramFeatureSummary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackPolicy {
    NotDeclared,
    NonExecutable,
    Executable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegmentInfo {
    index: u16,
    file_range: FileRange,
    vaddr: TargetAddr,
    memory_size: u64,
    align: u64,
    permissions: MemoryPermissions,
}

impl LoadSegmentInfo {
    pub const fn index(&self) -> u16 {
        self.index
    }

    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    pub const fn vaddr(&self) -> TargetAddr {
        self.vaddr
    }

    pub const fn memory_size(&self) -> u64 {
        self.memory_size
    }

    pub const fn align(&self) -> u64 {
        self.align
    }

    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicSegmentInfo {
    index: u16,
    file_range: FileRange,
    vaddr: TargetAddr,
    memory_size: u64,
}

impl DynamicSegmentInfo {
    pub const fn index(&self) -> u16 {
        self.index
    }

    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    pub const fn vaddr(&self) -> TargetAddr {
        self.vaddr
    }

    pub const fn memory_size(&self) -> u64 {
        self.memory_size
    }
}

#[derive(Debug)]
pub struct ParsedImage {
    header: crate::ElfHeaderInfo,
    load_segments: Vec<LoadSegmentInfo>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack_policy: StackPolicy,
    program_features: ProgramFeatureSummary,
}

impl ParsedImage {
    pub const fn header(&self) -> &crate::ElfHeaderInfo {
        &self.header
    }

    pub fn load_segments(&self) -> &[LoadSegmentInfo] {
        &self.load_segments
    }

    pub const fn dynamic(&self) -> Option<DynamicSegmentInfo> {
        self.dynamic
    }

    pub const fn relro(&self) -> Option<TargetRange> {
        self.relro
    }

    pub const fn stack_policy(&self) -> StackPolicy {
        self.stack_policy
    }

    pub const fn program_features(&self) -> &ProgramFeatureSummary {
        &self.program_features
    }
}

impl ImageLoader {
    pub fn inspect<R: ElfReader>(&self, artifact: &AdmittedArtifact<R>) -> LoadResult<ParsedImage> {
        artifact
            .ensure_snapshot()
            .map_err(|error| error.with_stage(LoadStage::Parse))?;
        let header = artifact.header();
        let count = header.program_header_count();
        let mut load_segments = Vec::new();
        load_segments
            .try_reserve_exact(usize::from(count))
            .map_err(|_| {
                LoadError::new(
                    LoadStage::Parse,
                    LoadErrorKind::OutOfMemory,
                    ErrorContext::None,
                )
            })?;

        let entry_size = usize::from(header.program_header_entry_size());
        let mut raw = [0; goblin::elf64::program_header::SIZEOF_PHDR];
        let mut dynamic = None;
        let mut relro = None;
        let mut stack_policy = StackPolicy::NotDeclared;
        let mut program_features = ProgramFeatureSummary::default();
        for index in 0..count {
            let offset = header
                .program_header_offset()
                .checked_add(u64::from(index) * u64::from(header.program_header_entry_size()))
                .ok_or_else(|| program_header_error(index, ProgramHeaderField::FileRange, 0))?;
            artifact
                .reader()
                .read_exact_at(offset, &mut raw[..entry_size])
                .map_err(|error| error.with_stage(LoadStage::Parse))?;
            let ph =
                ProgramHeaderFields::decode(&raw[..entry_size], header.class(), header.endian())?;

            match ph.program_type {
                PT_LOAD => {
                    let file_range = FileRange::new(ph.file_offset, ph.file_size);
                    file_range
                        .validate(artifact.file_len())
                        .map_err(|error| error.at(LoadStage::Parse))?;
                    TargetRange::new(TargetAddr::new(ph.vaddr), ph.memory_size)
                        .end()
                        .map_err(|error| error.at(LoadStage::Parse))?;
                    load_segments.push(LoadSegmentInfo {
                        index,
                        file_range,
                        vaddr: TargetAddr::new(ph.vaddr),
                        memory_size: ph.memory_size,
                        align: ph.align,
                        permissions: permissions_from_flags(ph.flags),
                    });
                }
                PT_DYNAMIC => {
                    if dynamic.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateDynamic,
                            ph.program_type.into(),
                        ));
                    }
                    let file_range = FileRange::new(ph.file_offset, ph.file_size);
                    file_range
                        .validate(artifact.file_len())
                        .map_err(|error| error.at(LoadStage::Parse))?;
                    TargetRange::new(TargetAddr::new(ph.vaddr), ph.memory_size)
                        .end()
                        .map_err(|error| error.at(LoadStage::Parse))?;
                    dynamic = Some(DynamicSegmentInfo {
                        index,
                        file_range,
                        vaddr: TargetAddr::new(ph.vaddr),
                        memory_size: ph.memory_size,
                    });
                }
                PT_GNU_RELRO => {
                    if relro.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateRelro,
                            ph.program_type.into(),
                        ));
                    }
                    let range = TargetRange::new(TargetAddr::new(ph.vaddr), ph.memory_size);
                    range.end().map_err(|error| error.at(LoadStage::Parse))?;
                    relro = Some(range);
                }
                PT_GNU_STACK => {
                    if stack_policy != StackPolicy::NotDeclared {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateStack,
                            ph.program_type.into(),
                        ));
                    }
                    if ph.flags & PF_X != 0 {
                        stack_policy = StackPolicy::Executable;
                        program_features.executable_stack = Some(index);
                    } else {
                        stack_policy = StackPolicy::NonExecutable;
                    }
                }
                PT_INTERP => {
                    let range = FileRange::new(ph.file_offset, ph.file_size);
                    range
                        .validate(artifact.file_len())
                        .map_err(|error| error.at(LoadStage::Parse))?;
                    if program_features
                        .interpreter
                        .replace((index, range))
                        .is_some()
                    {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::UnsupportedInterpreter,
                            ph.program_type.into(),
                        ));
                    }
                }
                PT_TLS => {
                    let file_range = FileRange::new(ph.file_offset, ph.file_size);
                    file_range
                        .validate(artifact.file_len())
                        .map_err(|error| error.at(LoadStage::Parse))?;
                    if ph.file_size > ph.memory_size {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::FileRange,
                            ph.file_size,
                        ));
                    }
                    let range = TargetRange::new(TargetAddr::new(ph.vaddr), ph.memory_size);
                    range.end().map_err(|error| error.at(LoadStage::Parse))?;
                    if program_features.tls.replace((index, range)).is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::UnsupportedTls,
                            ph.program_type.into(),
                        ));
                    }
                }
                _ => {}
            }
        }

        artifact
            .ensure_snapshot()
            .map_err(|error| error.with_stage(LoadStage::Parse))?;
        Ok(ParsedImage {
            header: *header,
            load_segments,
            dynamic,
            relro,
            stack_policy,
            program_features,
        })
    }
}

struct ProgramHeaderFields {
    program_type: u32,
    flags: u32,
    file_offset: u64,
    vaddr: u64,
    file_size: u64,
    memory_size: u64,
    align: u64,
}

impl ProgramHeaderFields {
    fn decode(bytes: &[u8], class: ElfClass, endian: Endian) -> LoadResult<Self> {
        Ok(match class {
            ElfClass::Elf32 => Self {
                program_type: parse_u32(bytes, 0, endian)?,
                file_offset: u64::from(parse_u32(bytes, 4, endian)?),
                vaddr: u64::from(parse_u32(bytes, 8, endian)?),
                file_size: u64::from(parse_u32(bytes, 16, endian)?),
                memory_size: u64::from(parse_u32(bytes, 20, endian)?),
                flags: parse_u32(bytes, 24, endian)?,
                align: u64::from(parse_u32(bytes, 28, endian)?),
            },
            ElfClass::Elf64 => Self {
                program_type: parse_u32(bytes, 0, endian)?,
                flags: parse_u32(bytes, 4, endian)?,
                file_offset: parse_u64(bytes, 8, endian)?,
                vaddr: parse_u64(bytes, 16, endian)?,
                file_size: parse_u64(bytes, 32, endian)?,
                memory_size: parse_u64(bytes, 40, endian)?,
                align: parse_u64(bytes, 48, endian)?,
            },
        })
    }
}

fn parse_u32(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u32> {
    read_u32(bytes, offset, endian).map_err(|error| error.at(LoadStage::Parse))
}

fn parse_u64(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u64> {
    read_u64(bytes, offset, endian).map_err(|error| error.at(LoadStage::Parse))
}

fn permissions_from_flags(flags: u32) -> MemoryPermissions {
    let mut permissions = MemoryPermissions::NONE;
    if flags & PF_R != 0 {
        permissions = permissions.union(MemoryPermissions::READ);
    }
    if flags & PF_W != 0 {
        permissions = permissions.union(MemoryPermissions::WRITE);
    }
    if flags & PF_X != 0 {
        permissions = permissions.union(MemoryPermissions::EXECUTE);
    }
    permissions
}

fn program_header_error(index: u16, field: ProgramHeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Parse,
        LoadErrorKind::BadElf,
        ErrorContext::ProgramHeader {
            index,
            field,
            value,
        },
    )
}
