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

mod fixture;

use goblin::elf::{header::ET_DYN, Elf};

use self::fixture::ElfFixtureBuilder;

#[test]
fn fixture_builder_emits_a_parseable_elf64_header() {
    let bytes = ElfFixtureBuilder::elf64(goblin::elf::header::EM_RISCV, ET_DYN).build();
    let elf = Elf::parse(&bytes).expect("fixture must contain a valid ELF header");

    assert_eq!(elf.header.e_machine, goblin::elf::header::EM_RISCV);
    assert_eq!(elf.header.e_type, ET_DYN);
    assert!(elf.is_64);
    assert!(elf.little_endian);
}

#[test]
fn legacy_loader_rejects_invalid_magic() {
    let mut bytes = ElfFixtureBuilder::elf64(goblin::elf::header::EM_RISCV, ET_DYN).build();
    bytes[0] = 0;
    let mut mapper = crate::MemoryMapper::new(None);

    assert!(crate::load_elf(&bytes, &mut mapper).is_err());
}
