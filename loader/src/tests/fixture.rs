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

pub struct ElfFixtureBuilder {
    bytes: Vec<u8>,
}

impl ElfFixtureBuilder {
    pub fn elf32(machine: u16, elf_type: u16) -> Self {
        let mut bytes = std::vec![0; goblin::elf32::header::SIZEOF_EHDR];
        initialize_ident(&mut bytes, goblin::elf::header::ELFCLASS32);

        write_u16(&mut bytes, 16, elf_type);
        write_u16(&mut bytes, 18, machine);
        write_u32(&mut bytes, 20, u32::from(goblin::elf::header::EV_CURRENT));
        write_u16(&mut bytes, 40, goblin::elf32::header::SIZEOF_EHDR as u16);
        write_u16(
            &mut bytes,
            42,
            goblin::elf32::program_header::SIZEOF_PHDR as u16,
        );

        Self { bytes }
    }

    pub fn elf64(machine: u16, elf_type: u16) -> Self {
        let mut bytes = std::vec![0; goblin::elf64::header::SIZEOF_EHDR];
        initialize_ident(&mut bytes, goblin::elf::header::ELFCLASS64);

        write_u16(&mut bytes, 16, elf_type);
        write_u16(&mut bytes, 18, machine);
        write_u32(&mut bytes, 20, u32::from(goblin::elf::header::EV_CURRENT));
        write_u16(&mut bytes, 52, goblin::elf64::header::SIZEOF_EHDR as u16);
        write_u16(
            &mut bytes,
            54,
            goblin::elf64::program_header::SIZEOF_PHDR as u16,
        );

        Self { bytes }
    }

    pub fn set_ident(mut self, index: usize, value: u8) -> Self {
        self.bytes[index] = value;
        self
    }

    pub fn set_type(mut self, value: u16) -> Self {
        write_u16(&mut self.bytes, 16, value);
        self
    }

    pub fn set_machine(mut self, value: u16) -> Self {
        write_u16(&mut self.bytes, 18, value);
        self
    }

    pub fn set_program_header_table(mut self, offset: u64, count: u16) -> Self {
        match self.bytes[goblin::elf::header::EI_CLASS] {
            goblin::elf::header::ELFCLASS32 => {
                write_u32(&mut self.bytes, 28, offset as u32);
                write_u16(&mut self.bytes, 44, count);
            }
            goblin::elf::header::ELFCLASS64 => {
                write_u64(&mut self.bytes, 32, offset);
                write_u16(&mut self.bytes, 56, count);
            }
            _ => unreachable!(),
        }
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.bytes
    }
}

fn initialize_ident(bytes: &mut [u8], class: u8) {
    bytes[..4].copy_from_slice(goblin::elf::header::ELFMAG);
    bytes[goblin::elf::header::EI_CLASS] = class;
    bytes[goblin::elf::header::EI_DATA] = goblin::elf::header::ELFDATA2LSB;
    bytes[goblin::elf::header::EI_VERSION] = goblin::elf::header::EV_CURRENT;
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
