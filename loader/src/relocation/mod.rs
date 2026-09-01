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

use crate::{
    address::TargetAddress,
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult},
    identity::{ElfClass, ElfData, ElfMachine},
    image::RelocationRecord,
    memory::{AllocationOffset, ImageMemory},
};

#[derive(Clone, Copy)]
pub(crate) enum WordWidth {
    U32,
    U64,
}

impl WordWidth {
    #[inline]
    pub const fn for_elf_class(class: ElfClass) -> Self {
        match class {
            ElfClass::Elf32 => Self::U32,
            ElfClass::Elf64 => Self::U64,
        }
    }

    #[inline]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }

    #[inline]
    pub const fn maximum(self) -> u64 {
        match self {
            Self::U32 => u32::MAX as u64,
            Self::U64 => u64::MAX,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AddendEncoding {
    Implicit,
    Explicit,
}

#[derive(Clone, Copy)]
pub(crate) struct TargetWord {
    width: WordWidth,
    endian: ElfData,
}

impl TargetWord {
    #[inline]
    pub const fn new(width: WordWidth, endian: ElfData) -> Self {
        Self { width, endian }
    }

    #[inline]
    pub const fn width(self) -> WordWidth {
        self.width
    }

    #[inline]
    pub const fn endian(self) -> ElfData {
        self.endian
    }

    pub fn read<M: ImageMemory>(self, memory: &M, offset: AllocationOffset) -> LoadResult<u64> {
        let mut bytes = [0; 8];
        let len = self.width.bytes() as usize;
        memory.read(offset, &mut bytes[..len])?;
        let word32 = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match (self.width, self.endian) {
            (WordWidth::U32, ElfData::Little) => u64::from(u32::from_le_bytes(word32)),
            (WordWidth::U32, ElfData::Big) => u64::from(u32::from_be_bytes(word32)),
            (WordWidth::U64, ElfData::Little) => u64::from_le_bytes(bytes),
            (WordWidth::U64, ElfData::Big) => u64::from_be_bytes(bytes),
        })
    }

    pub fn write<M: ImageMemory>(
        self,
        memory: &mut M,
        offset: AllocationOffset,
        value: u64,
    ) -> LoadResult<()> {
        if value > self.width.maximum() {
            return Err(LoadError::new(
                LoadErrorKind::IntegerOverflow,
                ErrorContext::MemoryAccess {
                    allocation_base: TargetAddress::new(0),
                    allocation_len: 0,
                    allocation_align: 0,
                    offset: offset.value(),
                    len: self.width.bytes(),
                },
            ));
        }
        let mut bytes = [0; 8];
        let len = self.width.bytes() as usize;
        match (self.width, self.endian) {
            (WordWidth::U32, ElfData::Little) => {
                bytes[..4].copy_from_slice(&(value as u32).to_le_bytes())
            }
            (WordWidth::U32, ElfData::Big) => {
                bytes[..4].copy_from_slice(&(value as u32).to_be_bytes())
            }
            (WordWidth::U64, ElfData::Little) => bytes.copy_from_slice(&value.to_le_bytes()),
            (WordWidth::U64, ElfData::Big) => bytes.copy_from_slice(&value.to_be_bytes()),
        }
        memory.write(offset, &bytes[..len])
    }
}

pub(crate) struct RelocationOperation {
    offset: AllocationOffset,
    value: u64,
    record: RelocationRecord,
}

impl RelocationOperation {
    #[inline]
    pub const fn new(offset: AllocationOffset, value: u64, record: RelocationRecord) -> Self {
        Self {
            offset,
            value,
            record,
        }
    }

    #[inline]
    pub const fn offset(&self) -> AllocationOffset {
        self.offset
    }

    #[inline]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[inline]
    pub const fn record(&self) -> RelocationRecord {
        self.record
    }
}

pub trait ArchRelocator {
    fn machine(&self) -> ElfMachine;

    fn class(&self) -> ElfClass;

    fn relative_type(&self) -> u32;

    fn addend_encoding(&self) -> AddendEncoding;
}
