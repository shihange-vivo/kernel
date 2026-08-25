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

use goblin::elf::header::{
    EI_CLASS, EI_DATA, EI_OSABI, EI_VERSION, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB,
    ELFMAG, ELFOSABI_SYSV, ET_DYN, ET_EXEC, EV_CURRENT,
};

use crate::{
    ElfReader, ErrorContext, HeaderField, LoadError, LoadErrorKind, LoadLimits, LoadResult,
    LoadStage,
};

const ELF32_HEADER_SIZE: usize = goblin::elf32::header::SIZEOF_EHDR;
const ELF64_HEADER_SIZE: usize = goblin::elf64::header::SIZEOF_EHDR;
const ELF_IDENT_SIZE: usize = 16;
const ELF32_PROGRAM_HEADER_SIZE: u16 = goblin::elf32::program_header::SIZEOF_PHDR as u16;
const ELF64_PROGRAM_HEADER_SIZE: u16 = goblin::elf64::program_header::SIZEOF_PHDR as u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageKind {
    StaticPie,
    FixedExec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactProfile {
    class: ElfClass,
    endian: Endian,
    machine: u16,
}

impl ArtifactProfile {
    pub const fn new(class: ElfClass, endian: Endian, machine: u16) -> Self {
        Self {
            class,
            endian,
            machine,
        }
    }

    pub const fn class(&self) -> ElfClass {
        self.class
    }

    pub const fn endian(&self) -> Endian {
        self.endian
    }

    pub const fn machine(&self) -> u16 {
        self.machine
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRequest {
    expected_kind: ImageKind,
    profile: ArtifactProfile,
    limits: LoadLimits,
}

impl ArtifactRequest {
    pub const fn new(
        expected_kind: ImageKind,
        profile: ArtifactProfile,
        limits: LoadLimits,
    ) -> Self {
        Self {
            expected_kind,
            profile,
            limits,
        }
    }

    pub const fn expected_kind(&self) -> ImageKind {
        self.expected_kind
    }

    pub const fn profile(&self) -> &ArtifactProfile {
        &self.profile
    }

    pub const fn limits(&self) -> &LoadLimits {
        &self.limits
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfHeaderInfo {
    class: ElfClass,
    endian: Endian,
    elf_type: u16,
    machine: u16,
    entry: u64,
    program_header_offset: u64,
    program_header_entry_size: u16,
    program_header_count: u16,
    flags: u32,
}

impl ElfHeaderInfo {
    pub const fn class(&self) -> ElfClass {
        self.class
    }

    pub const fn endian(&self) -> Endian {
        self.endian
    }

    pub const fn elf_type(&self) -> u16 {
        self.elf_type
    }

    pub const fn machine(&self) -> u16 {
        self.machine
    }

    pub const fn entry(&self) -> u64 {
        self.entry
    }

    pub const fn program_header_offset(&self) -> u64 {
        self.program_header_offset
    }

    pub const fn program_header_entry_size(&self) -> u16 {
        self.program_header_entry_size
    }

    pub const fn program_header_count(&self) -> u16 {
        self.program_header_count
    }

    pub const fn flags(&self) -> u32 {
        self.flags
    }
}

#[derive(Debug)]
pub struct AdmittedArtifact<R> {
    reader: R,
    header: ElfHeaderInfo,
    request: ArtifactRequest,
    file_len: u64,
}

impl<R> AdmittedArtifact<R> {
    pub const fn header(&self) -> &ElfHeaderInfo {
        &self.header
    }

    pub const fn request(&self) -> &ArtifactRequest {
        &self.request
    }

    pub const fn file_len(&self) -> u64 {
        self.file_len
    }

    pub(crate) const fn reader(&self) -> &R {
        &self.reader
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ImageLoader;

impl ImageLoader {
    pub const fn new() -> Self {
        Self
    }

    pub fn admit<R: ElfReader>(
        &self,
        reader: R,
        request: ArtifactRequest,
    ) -> LoadResult<AdmittedArtifact<R>> {
        let file_len = reader.len()?;
        request.limits.check_file_len(file_len)?;

        let mut ident = [0; ELF_IDENT_SIZE];
        reader.read_exact_at(0, &mut ident)?;
        let (class, endian) = validate_ident(&ident)?;
        let header_size = match class {
            ElfClass::Elf32 => ELF32_HEADER_SIZE,
            ElfClass::Elf64 => ELF64_HEADER_SIZE,
        };
        let mut bytes = [0; ELF64_HEADER_SIZE];
        reader.read_exact_at(0, &mut bytes[..header_size])?;
        let header = decode_header(&bytes[..header_size], class, endian)?;
        validate_header(&header, &request, file_len)?;

        Ok(AdmittedArtifact {
            reader,
            header,
            request,
            file_len,
        })
    }
}

fn validate_ident(ident: &[u8; ELF_IDENT_SIZE]) -> LoadResult<(ElfClass, Endian)> {
    if ident[..ELFMAG.len()] != ELFMAG[..] {
        return Err(bad_header(HeaderField::Magic, 0));
    }
    let class = match ident[EI_CLASS] {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        value => return Err(bad_header(HeaderField::Class, u64::from(value))),
    };
    let endian = match ident[EI_DATA] {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        value => return Err(bad_header(HeaderField::Endian, u64::from(value))),
    };
    if ident[EI_VERSION] != EV_CURRENT {
        return Err(bad_header(
            HeaderField::Version,
            u64::from(ident[EI_VERSION]),
        ));
    }
    if ident[EI_OSABI] != ELFOSABI_SYSV {
        return Err(unsupported_header(
            HeaderField::OsAbi,
            u64::from(ident[EI_OSABI]),
        ));
    }
    Ok((class, endian))
}

fn decode_header(bytes: &[u8], class: ElfClass, endian: Endian) -> LoadResult<ElfHeaderInfo> {
    let elf_type = read_u16(bytes, 16, endian)?;
    let machine = read_u16(bytes, 18, endian)?;
    let version = read_u32(bytes, 20, endian)?;
    if version != u32::from(EV_CURRENT) {
        return Err(bad_header(HeaderField::Version, u64::from(version)));
    }

    let (entry, program_header_offset, flags, header_size, ph_entry_size, ph_count) = match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(bytes, 24, endian)?),
            u64::from(read_u32(bytes, 28, endian)?),
            read_u32(bytes, 36, endian)?,
            read_u16(bytes, 40, endian)?,
            read_u16(bytes, 42, endian)?,
            read_u16(bytes, 44, endian)?,
        ),
        ElfClass::Elf64 => (
            read_u64(bytes, 24, endian)?,
            read_u64(bytes, 32, endian)?,
            read_u32(bytes, 48, endian)?,
            read_u16(bytes, 52, endian)?,
            read_u16(bytes, 54, endian)?,
            read_u16(bytes, 56, endian)?,
        ),
    };
    let expected_header_size = match class {
        ElfClass::Elf32 => ELF32_HEADER_SIZE as u16,
        ElfClass::Elf64 => ELF64_HEADER_SIZE as u16,
    };
    let expected_ph_entry_size = match class {
        ElfClass::Elf32 => ELF32_PROGRAM_HEADER_SIZE,
        ElfClass::Elf64 => ELF64_PROGRAM_HEADER_SIZE,
    };
    if header_size != expected_header_size {
        return Err(bad_header(HeaderField::HeaderSize, u64::from(header_size)));
    }
    if ph_entry_size != expected_ph_entry_size {
        return Err(bad_header(
            HeaderField::ProgramHeaderSize,
            u64::from(ph_entry_size),
        ));
    }

    Ok(ElfHeaderInfo {
        class,
        endian,
        elf_type,
        machine,
        entry,
        program_header_offset,
        program_header_entry_size: ph_entry_size,
        program_header_count: ph_count,
        flags,
    })
}

fn validate_header(
    header: &ElfHeaderInfo,
    request: &ArtifactRequest,
    file_len: u64,
) -> LoadResult<()> {
    let expected_type = match request.expected_kind {
        ImageKind::StaticPie => ET_DYN,
        ImageKind::FixedExec => ET_EXEC,
    };
    if header.elf_type != expected_type {
        return Err(unsupported_header(
            HeaderField::Type,
            u64::from(header.elf_type),
        ));
    }
    if header.class != request.profile.class {
        return Err(unsupported_header(HeaderField::Class, header.class as u64));
    }
    if header.endian != request.profile.endian {
        return Err(unsupported_header(
            HeaderField::Endian,
            header.endian as u64,
        ));
    }
    if header.machine != request.profile.machine {
        return Err(unsupported_header(
            HeaderField::Machine,
            u64::from(header.machine),
        ));
    }
    request
        .limits
        .check_program_header_count(header.program_header_count)?;

    let table_len = u64::from(header.program_header_entry_size)
        .checked_mul(u64::from(header.program_header_count))
        .ok_or_else(|| {
            LoadError::new(
                LoadStage::Validate,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::HeaderField {
                    field: HeaderField::ProgramHeaderTable,
                    value: header.program_header_offset,
                },
            )
        })?;
    let table_end = header
        .program_header_offset
        .checked_add(table_len)
        .ok_or_else(|| {
            LoadError::new(
                LoadStage::Validate,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::FileRange {
                    offset: header.program_header_offset,
                    len: table_len,
                    file_len,
                },
            )
        })?;
    if table_end > file_len {
        return Err(LoadError::new(
            LoadStage::Validate,
            LoadErrorKind::OutOfBounds,
            ErrorContext::FileRange {
                offset: header.program_header_offset,
                len: table_len,
                file_len,
            },
        ));
    }
    Ok(())
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u16> {
    let raw = read_array::<2>(bytes, offset)?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(raw),
        Endian::Big => u16::from_be_bytes(raw),
    })
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u32> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(raw),
        Endian::Big => u32::from_be_bytes(raw),
    })
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize, endian: Endian) -> LoadResult<u64> {
    let raw = read_array::<8>(bytes, offset)?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(raw),
        Endian::Big => u64::from_be_bytes(raw),
    })
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> LoadResult<[u8; N]> {
    let end = offset.checked_add(N).ok_or_else(|| {
        LoadError::new(
            LoadStage::Parse,
            LoadErrorKind::IntegerOverflow,
            ErrorContext::None,
        )
    })?;
    let src = bytes.get(offset..end).ok_or_else(|| {
        LoadError::new(
            LoadStage::Parse,
            LoadErrorKind::OutOfBounds,
            ErrorContext::FileRange {
                offset: offset as u64,
                len: N as u64,
                file_len: bytes.len() as u64,
            },
        )
    })?;
    let mut raw = [0; N];
    raw.copy_from_slice(src);
    Ok(raw)
}

fn bad_header(field: HeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Parse,
        LoadErrorKind::BadElf,
        ErrorContext::HeaderField { field, value },
    )
}

fn unsupported_header(field: HeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Validate,
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::HeaderField { field, value },
    )
}
