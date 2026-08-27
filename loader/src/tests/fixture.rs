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

use std::vec::Vec;

use goblin::{
    elf::header::{
        EI_CLASS, EI_DATA, EI_VERSION, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFMAG, EV_CURRENT,
    },
    elf32, elf64,
};

pub struct ElfFixtureBuilder {
    bytes: Vec<u8>,
}

impl ElfFixtureBuilder {
    pub fn elf64(e_machine: u16, e_type: u16) -> Self {
        let mut bytes = std::vec![0; elf64::header::SIZEOF_EHDR];
        bytes[..4].copy_from_slice(ELFMAG);
        bytes[EI_CLASS] = ELFCLASS64;
        bytes[EI_DATA] = ELFDATA2LSB;
        bytes[EI_VERSION] = EV_CURRENT;

        write_u16(&mut bytes, 16, e_type);
        write_u16(&mut bytes, 18, e_machine);
        write_u32(&mut bytes, 20, EV_CURRENT as u32);
        write_u16(&mut bytes, 52, elf64::header::SIZEOF_EHDR as u16);
        write_u16(&mut bytes, 54, elf64::program_header::SIZEOF_PHDR as u16);
        write_u16(&mut bytes, 58, elf64::section_header::SIZEOF_SHDR as u16);

        Self { bytes }
    }

    pub fn elf32(e_machine: u16, e_type: u16) -> Self {
        let mut bytes = std::vec![0; elf32::header::SIZEOF_EHDR];
        bytes[..4].copy_from_slice(ELFMAG);
        bytes[EI_CLASS] = ELFCLASS32;
        bytes[EI_DATA] = ELFDATA2LSB;
        bytes[EI_VERSION] = EV_CURRENT;

        write_u16(&mut bytes, 16, e_type);
        write_u16(&mut bytes, 18, e_machine);
        write_u32(&mut bytes, 20, EV_CURRENT as u32);
        write_u16(&mut bytes, 40, elf32::header::SIZEOF_EHDR as u16);
        write_u16(&mut bytes, 42, elf32::program_header::SIZEOF_PHDR as u16);
        write_u16(&mut bytes, 46, elf32::section_header::SIZEOF_SHDR as u16);

        Self { bytes }
    }

    pub fn build(self) -> Vec<u8> {
        self.bytes
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
