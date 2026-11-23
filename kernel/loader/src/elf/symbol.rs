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

//! On-disk ELF symbol entry sizes and field decoding.

use goblin::{elf32, elf64};

use super::ElfClass;
#[cfg(test)]
use super::{read_array, read_u16, read_u32, read_u64, ElfData};
#[cfg(test)]
use crate::LoadResult;
#[cfg(test)]
use goblin::elf::sym::{st_bind, st_type};

pub(super) const fn symbol_entry_size(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => elf32::sym::SIZEOF_SYM as u64,
        ElfClass::Elf64 => elf64::sym::SIZEOF_SYM as u64,
    }
}

// Exercised by the format tests until the dynamic table reader consumes records.
#[cfg(test)]
struct SymbolRecord {
    name_offset: u32,
    value: u64,
    size: u64,
    info: u8,
    // Preserve the whole st_other byte for later visibility and ABI checks.
    other: u8,
    section_index: u16,
}

#[cfg(test)]
impl SymbolRecord {
    fn decode(bytes: &[u8], class: ElfClass, endian: ElfData) -> LoadResult<Self> {
        let name_offset = read_u32(bytes, 0, endian)?;
        Ok(match class {
            ElfClass::Elf32 => {
                let [info, other] = read_array(bytes, 12)?;
                Self {
                    name_offset,
                    value: u64::from(read_u32(bytes, 4, endian)?),
                    size: u64::from(read_u32(bytes, 8, endian)?),
                    info,
                    other,
                    section_index: read_u16(bytes, 14, endian)?,
                }
            }
            ElfClass::Elf64 => {
                let [info, other] = read_array(bytes, 4)?;
                Self {
                    name_offset,
                    value: read_u64(bytes, 8, endian)?,
                    size: read_u64(bytes, 16, endian)?,
                    info,
                    other,
                    section_index: read_u16(bytes, 6, endian)?,
                }
            }
        })
    }

    fn binding(&self) -> u8 {
        st_bind(self.info)
    }

    fn kind(&self) -> u8 {
        st_type(self.info)
    }
}

#[cfg(test)]
mod tests {
    use blueos_test_macro::test;
    use goblin::elf::{
        section_header::SHN_ABS,
        sym::{STB_WEAK, STT_OBJECT},
    };

    use super::*;
    use crate::error::LoadErrorKind;

    #[test]
    fn symbol_records_decode_both_classes_and_byte_orders() {
        #[rustfmt::skip]
        let elf32_le = [
            0x04, 0x03, 0x02, 0x01, // st_name
            0xef, 0xcd, 0xab, 0x89, // st_value
            0x78, 0x56, 0x34, 0x12, // st_size
            0x21, 0x83, 0xf1, 0xff, // st_info, st_other, st_shndx
        ];
        #[rustfmt::skip]
        let elf32_be = [
            0x01, 0x02, 0x03, 0x04,
            0x89, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78,
            0x21, 0x83, 0xff, 0xf1,
        ];
        #[rustfmt::skip]
        let elf64_le = [
            0x04, 0x03, 0x02, 0x01, // st_name
            0x21, 0x83, 0xf1, 0xff, // st_info, st_other, st_shndx
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, // st_value
            0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a, // st_size
        ];
        #[rustfmt::skip]
        let elf64_be = [
            0x01, 0x02, 0x03, 0x04,
            0x21, 0x83, 0xff, 0xf1,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
        ];

        for (class, endian, bytes, value, size) in [
            (
                ElfClass::Elf32,
                ElfData::Little,
                elf32_le.as_slice(),
                0x89ab_cdef,
                0x1234_5678,
            ),
            (
                ElfClass::Elf32,
                ElfData::Big,
                elf32_be.as_slice(),
                0x89ab_cdef,
                0x1234_5678,
            ),
            (
                ElfClass::Elf64,
                ElfData::Little,
                elf64_le.as_slice(),
                0x0123_4567_89ab_cdef,
                0x9abc_def0_1234_5678,
            ),
            (
                ElfClass::Elf64,
                ElfData::Big,
                elf64_be.as_slice(),
                0x0123_4567_89ab_cdef,
                0x9abc_def0_1234_5678,
            ),
        ] {
            assert_eq!(symbol_entry_size(class), bytes.len() as u64);
            let record = SymbolRecord::decode(bytes, class, endian).unwrap();
            assert_eq!(record.name_offset, 0x0102_0304);
            assert_eq!(record.value, value);
            assert_eq!(record.size, size);
            assert_eq!(record.binding(), STB_WEAK);
            assert_eq!(record.kind(), STT_OBJECT);
            assert_eq!(record.other, 0x83);
            assert_eq!(u32::from(record.section_index), SHN_ABS);
        }
    }

    #[test]
    fn symbol_records_reject_every_truncated_prefix() {
        let bytes = [0; 24];
        for (class, size) in [(ElfClass::Elf32, 16), (ElfClass::Elf64, 24)] {
            for len in 0..size {
                let result = SymbolRecord::decode(&bytes[..len], class, ElfData::Little);
                assert!(matches!(result, Err(error) if error.kind() == LoadErrorKind::OutOfBounds));
            }
        }
    }
}
