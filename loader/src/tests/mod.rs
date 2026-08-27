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

use goblin::elf::{
    header::{EM_ARM, EM_RISCV, ET_DYN},
    Elf,
};

use crate::tests::fixture::ElfFixtureBuilder;

mod fixture;

#[test]
fn fixture_builder_emits_a_parseable_elf64_header() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    let elf = Elf::parse(&bytes).expect("fixture must contain a valid ELF header");

    assert_eq!(elf.header.e_machine, EM_RISCV);
    assert_eq!(elf.header.e_type, ET_DYN);
    assert!(elf.is_64);
    assert!(elf.little_endian);
}

#[test]
fn fixture_builder_emits_a_parseable_elf32_header() {
    let bytes = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN).build();
    let elf = Elf::parse(&bytes).expect("fixture must contain a valid ELF header");

    assert_eq!(elf.header.e_machine, EM_ARM);
    assert_eq!(elf.header.e_type, ET_DYN);
    assert!(!elf.is_64);
    assert!(elf.little_endian);
}
