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

mod arm;
mod riscv;

use alloc::vec::Vec;

use crate::{
    ElfClass, Endian, ErrorContext, ImageLoadTransaction, ImageMemory, LoadError, LoadErrorKind,
    LoadResult, LoadStage, MappedImage, MemoryPermissions, RelocationAddend, RelocationRecord,
    RuntimeImage, RuntimeImageMetadata, TargetLocation,
};

pub use arm::ArmRelocator;
pub use riscv::Riscv64Relocator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordWidth {
    U32,
    U64,
}

impl WordWidth {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }

    const fn maximum(self) -> u64 {
        match self {
            Self::U32 => u32::MAX as u64,
            Self::U64 => u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddendEncoding {
    Implicit,
    Explicit,
}

pub trait ArchRelocator {
    fn machine(&self) -> u16;

    fn class(&self) -> ElfClass;

    fn word_width(&self) -> WordWidth;

    fn relative_type(&self) -> u32;

    fn addend_encoding(&self) -> AddendEncoding;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetWord {
    width: WordWidth,
    endian: Endian,
}

impl TargetWord {
    pub const fn new(width: WordWidth, endian: Endian) -> Self {
        Self { width, endian }
    }

    pub const fn width(self) -> WordWidth {
        self.width
    }

    pub const fn endian(self) -> Endian {
        self.endian
    }

    pub fn read<M: ImageMemory>(self, memory: &M, location: TargetLocation) -> LoadResult<u64> {
        let mut bytes = [0; 8];
        let len = self.width.bytes() as usize;
        memory.read(location, &mut bytes[..len])?;
        Ok(match (self.width, self.endian) {
            (WordWidth::U32, Endian::Little) => {
                u64::from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
            }
            (WordWidth::U32, Endian::Big) => {
                u64::from(u32::from_be_bytes(bytes[..4].try_into().unwrap()))
            }
            (WordWidth::U64, Endian::Little) => u64::from_le_bytes(bytes),
            (WordWidth::U64, Endian::Big) => u64::from_be_bytes(bytes),
        })
    }

    pub fn write<M: ImageMemory>(
        self,
        memory: &mut M,
        location: TargetLocation,
        value: u64,
    ) -> LoadResult<()> {
        if value > self.width.maximum() {
            return Err(LoadError::new(
                LoadStage::Relocate,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::MemoryAccess {
                    allocation: location.allocation(),
                    offset: location.offset(),
                    len: self.width.bytes(),
                },
            ));
        }
        let mut bytes = [0; 8];
        let len = self.width.bytes() as usize;
        match (self.width, self.endian) {
            (WordWidth::U32, Endian::Little) => {
                bytes[..4].copy_from_slice(&(value as u32).to_le_bytes())
            }
            (WordWidth::U32, Endian::Big) => {
                bytes[..4].copy_from_slice(&(value as u32).to_be_bytes())
            }
            (WordWidth::U64, Endian::Little) => bytes.copy_from_slice(&value.to_le_bytes()),
            (WordWidth::U64, Endian::Big) => bytes.copy_from_slice(&value.to_be_bytes()),
        }
        memory.write(location, &bytes[..len])
    }
}

#[derive(Debug)]
pub struct RelocatedImage {
    mapped: MappedImage,
    metadata: RuntimeImageMetadata,
}

impl RelocatedImage {
    pub const fn mapped(&self) -> &MappedImage {
        &self.mapped
    }

    pub const fn metadata(&self) -> &RuntimeImageMetadata {
        &self.metadata
    }

    pub(crate) fn into_parts(self) -> (MappedImage, RuntimeImageMetadata) {
        (self.mapped, self.metadata)
    }
}

impl RuntimeImage {
    pub fn relocate<M, A>(
        self,
        transaction: &mut ImageLoadTransaction<'_, M>,
        relocator: &A,
    ) -> LoadResult<RelocatedImage>
    where
        M: ImageMemory,
        A: ArchRelocator + ?Sized,
    {
        let (mapped, metadata) = self.into_parts();
        validate_relocator(&mapped, relocator)?;
        let target_word =
            TargetWord::new(relocator.word_width(), mapped.request().profile().endian());
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(metadata.relocations().len())
            .map_err(|_| {
                LoadError::new(
                    LoadStage::Relocate,
                    LoadErrorKind::OutOfMemory,
                    ErrorContext::None,
                )
            })?;

        for record in metadata.relocations() {
            operations.push(preflight_relative(
                &mapped,
                *record,
                relocator,
                target_word,
                transaction.memory(),
            )?);
        }
        for operation in operations {
            target_word.write(transaction.memory(), operation.location, operation.value)?;
        }

        Ok(RelocatedImage { mapped, metadata })
    }
}

#[derive(Clone, Copy, Debug)]
struct RelocationOperation {
    location: TargetLocation,
    value: u64,
}

fn validate_relocator<A: ArchRelocator + ?Sized>(
    mapped: &MappedImage,
    relocator: &A,
) -> LoadResult<()> {
    let profile = mapped.request().profile();
    let expected_width = match profile.class() {
        ElfClass::Elf32 => WordWidth::U32,
        ElfClass::Elf64 => WordWidth::U64,
    };
    if relocator.machine() == profile.machine()
        && relocator.class() == profile.class()
        && relocator.word_width() == expected_width
    {
        Ok(())
    } else {
        Err(LoadError::new(
            LoadStage::Relocate,
            LoadErrorKind::UnsupportedByProfile,
            ErrorContext::HeaderField {
                field: crate::HeaderField::Machine,
                value: u64::from(profile.machine()),
            },
        ))
    }
}

fn preflight_relative<M, A>(
    mapped: &MappedImage,
    record: RelocationRecord,
    relocator: &A,
    target_word: TargetWord,
    memory: &M,
) -> LoadResult<RelocationOperation>
where
    M: ImageMemory,
    A: ArchRelocator + ?Sized,
{
    if record.raw_type() != relocator.relative_type() || record.symbol_index() != 0 {
        return Err(relocation_error(
            record,
            LoadErrorKind::UnsupportedByProfile,
        ));
    }
    let addend = match (relocator.addend_encoding(), record.addend()) {
        (AddendEncoding::Explicit, RelocationAddend::Explicit(value)) => i128::from(value),
        (AddendEncoding::Implicit, RelocationAddend::Implicit) => {
            let location = checked_target(mapped, record, target_word, memory, true)?;
            i128::from(target_word.read(memory, location)?)
        }
        _ => {
            return Err(relocation_error(
                record,
                LoadErrorKind::UnsupportedByProfile,
            ));
        }
    };
    let location = checked_target(mapped, record, target_word, memory, false)?;
    let result = i128::from(mapped.load_bias().get())
        .checked_add(addend)
        .filter(|value| *value >= 0 && *value <= i128::from(target_word.width.maximum()))
        .ok_or_else(|| relocation_error(record, LoadErrorKind::IntegerOverflow))?;
    Ok(RelocationOperation {
        location,
        value: result as u64,
    })
}

fn checked_target<M: ImageMemory>(
    mapped: &MappedImage,
    record: RelocationRecord,
    target_word: TargetWord,
    memory: &M,
    read: bool,
) -> LoadResult<TargetLocation> {
    if record.offset().get() % target_word.width.bytes() != 0 {
        return Err(relocation_error(record, LoadErrorKind::InvalidAlignment));
    }
    let location = mapped
        .locate_vaddr(
            record.offset(),
            target_word.width.bytes(),
            MemoryPermissions::WRITE,
        )
        .map_err(|_| relocation_error(record, LoadErrorKind::OutOfBounds))?;
    let permissions = if read {
        MemoryPermissions::READ.bitor(MemoryPermissions::WRITE)
    } else {
        MemoryPermissions::WRITE
    };
    memory
        .validate_access(location, target_word.width.bytes(), permissions)
        .map_err(|_| relocation_error(record, LoadErrorKind::OutOfBounds))?;
    Ok(location)
}

fn relocation_error(record: RelocationRecord, kind: LoadErrorKind) -> LoadError {
    LoadError::new(
        LoadStage::Relocate,
        kind,
        ErrorContext::Relocation {
            offset: record.offset(),
            raw_type: record.raw_type(),
            symbol_index: record.symbol_index(),
        },
    )
}
