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
    EI_ABIVERSION, EI_CLASS, EI_DATA, EI_OSABI, EI_VERSION, ELFCLASS32, ELFCLASS64, ELFDATA2LSB,
    ELFDATA2MSB, ELFMAG, ELFOSABI_SYSV, ET_DYN, ET_EXEC, EV_CURRENT,
};

use crate::{
    ElfReader, ErrorContext, HeaderField, LoadError, LoadErrorKind, LoadLimits, LoadResult,
    LoadStage, RangeError, RangeResult, SourceSnapshot,
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

impl ElfClass {
    pub const fn elf_class_encoding(self) -> u8 {
        match self {
            Self::Elf32 => ELFCLASS32,
            Self::Elf64 => ELFCLASS64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub const fn elf_data_encoding(self) -> u8 {
        match self {
            Self::Little => ELFDATA2LSB,
            Self::Big => ELFDATA2MSB,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedElfType {
    Dyn,
    Exec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderFlagsPolicy {
    allowed_mask: u32,
    required_mask: u32,
    required_value: u32,
}

impl HeaderFlagsPolicy {
    pub const PERMISSIVE: Self = Self::new(u32::MAX, 0, 0);

    pub const fn new(allowed_mask: u32, required_mask: u32, required_value: u32) -> Self {
        Self {
            allowed_mask,
            required_mask,
            required_value,
        }
    }

    pub const fn exact(value: u32) -> Self {
        Self::new(value, u32::MAX, value)
    }

    pub const fn accepts(self, value: u32) -> bool {
        self.required_value & !self.required_mask == 0
            && value & !self.allowed_mask == 0
            && value & self.required_mask == self.required_value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryMode {
    Direct {
        instruction_alignment: u8,
        minimum_instruction_size: u8,
    },
    Thumb {
        instruction_alignment: u8,
        minimum_instruction_size: u8,
    },
}

impl EntryMode {
    pub const fn direct(instruction_alignment: u8, minimum_instruction_size: u8) -> Self {
        Self::Direct {
            instruction_alignment,
            minimum_instruction_size,
        }
    }

    pub const fn thumb(instruction_alignment: u8, minimum_instruction_size: u8) -> Self {
        Self::Thumb {
            instruction_alignment,
            minimum_instruction_size,
        }
    }

    pub const fn instruction_alignment(self) -> u64 {
        match self {
            Self::Direct {
                instruction_alignment,
                ..
            }
            | Self::Thumb {
                instruction_alignment,
                ..
            } => instruction_alignment as u64,
        }
    }

    pub const fn minimum_instruction_size(self) -> u64 {
        match self {
            Self::Direct {
                minimum_instruction_size,
                ..
            }
            | Self::Thumb {
                minimum_instruction_size,
                ..
            } => minimum_instruction_size as u64,
        }
    }

    pub const fn canonical_entry(self, entry: u64) -> u64 {
        match self {
            Self::Direct { .. } => entry,
            Self::Thumb { .. } => entry & !1,
        }
    }

    const fn accepts(self, entry: u64) -> bool {
        let alignment = self.instruction_alignment();
        let minimum_instruction_size = self.minimum_instruction_size();
        let encoding_valid = match self {
            Self::Direct { .. } => true,
            Self::Thumb { .. } => entry & 1 == 1,
        };
        encoding_valid
            && alignment.is_power_of_two()
            && minimum_instruction_size != 0
            && self.canonical_entry(entry) % alignment == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelativeValuePolicy {
    allow_null: bool,
    allow_one_past: bool,
}

impl RelativeValuePolicy {
    pub const SAME_IMAGE: Self = Self::new(false, false);

    pub const fn new(allow_null: bool, allow_one_past: bool) -> Self {
        Self {
            allow_null,
            allow_one_past,
        }
    }

    pub const fn allows_null(self) -> bool {
        self.allow_null
    }

    pub const fn allows_one_past(self) -> bool {
        self.allow_one_past
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactProfile {
    class: ElfClass,
    endian: Endian,
    machine: u16,
    header_flags: HeaderFlagsPolicy,
    entry_mode: EntryMode,
    minimum_image_alignment: u64,
    relative_values: RelativeValuePolicy,
}

impl ArtifactProfile {
    /// Build an explicit machine profile without architecture-dependent defaults.
    pub const fn new(
        class: ElfClass,
        endian: Endian,
        machine: u16,
        header_flags: HeaderFlagsPolicy,
        entry_mode: EntryMode,
        minimum_image_alignment: u64,
        relative_values: RelativeValuePolicy,
    ) -> Self {
        Self {
            class,
            endian,
            machine,
            header_flags,
            entry_mode,
            minimum_image_alignment,
            relative_values,
        }
    }

    /// RISC-V integer soft-float baseline without compressed instructions or
    /// any other ELF architecture flags.
    pub const fn riscv_soft(class: ElfClass) -> Self {
        Self::new(
            class,
            Endian::Little,
            goblin::elf::header::EM_RISCV,
            HeaderFlagsPolicy::exact(0),
            EntryMode::direct(4, 4),
            4,
            RelativeValuePolicy::SAME_IMAGE,
        )
    }

    /// BlueOS RISC-V baseline with the compressed-instruction extension and
    /// the integer soft-float ABI. Requiring `EF_RISCV_RVC` keeps the entry
    /// alignment rule coupled to the advertised instruction encoding.
    pub const fn riscv_compressed_soft(class: ElfClass) -> Self {
        const EF_RISCV_RVC: u32 = 0x0000_0001;

        Self::new(
            class,
            Endian::Little,
            goblin::elf::header::EM_RISCV,
            HeaderFlagsPolicy::exact(EF_RISCV_RVC),
            EntryMode::direct(2, 2),
            4,
            RelativeValuePolicy::SAME_IMAGE,
        )
    }

    /// BlueOS Cortex-M baseline: ARM EABI5, Thumb-only, soft-float calling
    /// convention, and no unrecognized architecture flag bits.
    pub const fn arm_thumb_v7m_soft() -> Self {
        const EF_ARM_EABIMASK: u32 = 0xff00_0000;
        const EF_ARM_EABI_VER5: u32 = 0x0500_0000;
        const EF_ARM_ABI_FLOAT_SOFT: u32 = 0x0000_0200;

        Self::new(
            ElfClass::Elf32,
            Endian::Little,
            goblin::elf::header::EM_ARM,
            HeaderFlagsPolicy::new(
                EF_ARM_EABIMASK | EF_ARM_ABI_FLOAT_SOFT,
                EF_ARM_EABIMASK | EF_ARM_ABI_FLOAT_SOFT,
                EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_SOFT,
            ),
            EntryMode::thumb(2, 2),
            4,
            RelativeValuePolicy::SAME_IMAGE,
        )
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

    pub const fn header_flags(&self) -> HeaderFlagsPolicy {
        self.header_flags
    }

    pub const fn entry_mode(&self) -> EntryMode {
        self.entry_mode
    }

    pub const fn minimum_image_alignment(&self) -> u64 {
        self.minimum_image_alignment
    }

    pub const fn relative_value_policy(&self) -> RelativeValuePolicy {
        self.relative_values
    }
}

/// ELF admission profile and resource limits for one artifact.
///
/// Deployment properties such as instruction-cache publication scope belong
/// to the cache/publisher adapter, not this source identity request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRequest {
    expected_elf_type: ExpectedElfType,
    profile: ArtifactProfile,
    limits: LoadLimits,
}

impl ArtifactRequest {
    pub const fn new(
        expected_elf_type: ExpectedElfType,
        profile: ArtifactProfile,
        limits: LoadLimits,
    ) -> Self {
        Self {
            expected_elf_type,
            profile,
            limits,
        }
    }

    pub const fn expected_elf_type(&self) -> ExpectedElfType {
        self.expected_elf_type
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
    snapshot: SourceSnapshot,
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

impl<R: ElfReader> AdmittedArtifact<R> {
    pub(crate) fn ensure_snapshot(&self) -> LoadResult<()> {
        if self
            .reader
            .snapshot()
            .map_err(|error| error.with_stage(LoadStage::Read))?
            == self.snapshot
        {
            Ok(())
        } else {
            Err(LoadError::new(
                LoadStage::Read,
                LoadErrorKind::SourceChanged,
                ErrorContext::None,
            ))
        }
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
        let snapshot = reader
            .snapshot()
            .map_err(|error| error.with_stage(LoadStage::Read))?;
        let file_len = reader
            .len()
            .map_err(|error| error.with_stage(LoadStage::Read))?;
        request.limits.check_file_len(file_len)?;

        let mut ident = [0; ELF_IDENT_SIZE];
        reader
            .read_exact_at(0, &mut ident)
            .map_err(|error| error.with_stage(LoadStage::Read))?;
        let (class, endian) = validate_ident(&ident)?;
        let header_size = match class {
            ElfClass::Elf32 => ELF32_HEADER_SIZE,
            ElfClass::Elf64 => ELF64_HEADER_SIZE,
        };
        let mut bytes = [0; ELF64_HEADER_SIZE];
        reader
            .read_exact_at(0, &mut bytes[..header_size])
            .map_err(|error| error.with_stage(LoadStage::Read))?;
        let header = decode_header(&bytes[..header_size], class, endian)?;
        validate_header(&header, &request, file_len)?;
        if reader
            .snapshot()
            .map_err(|error| error.with_stage(LoadStage::Read))?
            != snapshot
        {
            return Err(LoadError::new(
                LoadStage::Read,
                LoadErrorKind::SourceChanged,
                ErrorContext::None,
            ));
        }

        Ok(AdmittedArtifact {
            reader,
            header,
            request,
            file_len,
            snapshot,
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
    if ident[EI_ABIVERSION] != 0 {
        return Err(unsupported_header(
            HeaderField::AbiVersion,
            u64::from(ident[EI_ABIVERSION]),
        ));
    }
    Ok((class, endian))
}

fn decode_header(bytes: &[u8], class: ElfClass, endian: Endian) -> LoadResult<ElfHeaderInfo> {
    let elf_type = at_parse(read_u16(bytes, 16, endian))?;
    let machine = at_parse(read_u16(bytes, 18, endian))?;
    let version = at_parse(read_u32(bytes, 20, endian))?;
    if version != u32::from(EV_CURRENT) {
        return Err(bad_header(HeaderField::Version, u64::from(version)));
    }

    let (entry, program_header_offset, flags, header_size, ph_entry_size, ph_count) = match class {
        ElfClass::Elf32 => (
            u64::from(at_parse(read_u32(bytes, 24, endian))?),
            u64::from(at_parse(read_u32(bytes, 28, endian))?),
            at_parse(read_u32(bytes, 36, endian))?,
            at_parse(read_u16(bytes, 40, endian))?,
            at_parse(read_u16(bytes, 42, endian))?,
            at_parse(read_u16(bytes, 44, endian))?,
        ),
        ElfClass::Elf64 => (
            at_parse(read_u64(bytes, 24, endian))?,
            at_parse(read_u64(bytes, 32, endian))?,
            at_parse(read_u32(bytes, 48, endian))?,
            at_parse(read_u16(bytes, 52, endian))?,
            at_parse(read_u16(bytes, 54, endian))?,
            at_parse(read_u16(bytes, 56, endian))?,
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
    let expected_type = match request.expected_elf_type {
        ExpectedElfType::Dyn => ET_DYN,
        ExpectedElfType::Exec => ET_EXEC,
    };
    if header.elf_type != expected_type {
        return Err(unsupported_header(
            HeaderField::Type,
            u64::from(header.elf_type),
        ));
    }
    if header.class != request.profile.class {
        return Err(unsupported_header(
            HeaderField::Class,
            u64::from(header.class.elf_class_encoding()),
        ));
    }
    if header.endian != request.profile.endian {
        return Err(unsupported_header(
            HeaderField::Endian,
            u64::from(header.endian.elf_data_encoding()),
        ));
    }
    if header.machine != request.profile.machine {
        return Err(unsupported_header(
            HeaderField::Machine,
            u64::from(header.machine),
        ));
    }
    if !request.profile.header_flags.accepts(header.flags) {
        return Err(unsupported_header(
            HeaderField::Flags,
            u64::from(header.flags),
        ));
    }
    if !request.profile.entry_mode.accepts(header.entry) {
        return Err(unsupported_header(HeaderField::Entry, header.entry));
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

pub(crate) fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> RangeResult<u16> {
    let raw = read_array::<2>(bytes, offset)?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(raw),
        Endian::Big => u16::from_be_bytes(raw),
    })
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> RangeResult<u32> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(raw),
        Endian::Big => u32::from_be_bytes(raw),
    })
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize, endian: Endian) -> RangeResult<u64> {
    let raw = read_array::<8>(bytes, offset)?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(raw),
        Endian::Big => u64::from_be_bytes(raw),
    })
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> RangeResult<[u8; N]> {
    let end = offset.checked_add(N).ok_or_else(|| {
        RangeError::new(
            LoadErrorKind::IntegerOverflow,
            ErrorContext::FileRange {
                offset: offset as u64,
                len: N as u64,
                file_len: bytes.len() as u64,
            },
        )
    })?;
    let src = bytes.get(offset..end).ok_or_else(|| {
        RangeError::new(
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

fn at_parse<T>(result: RangeResult<T>) -> LoadResult<T> {
    result.map_err(|error| error.at(LoadStage::Parse))
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
