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

use goblin::elf::{
    header::{EI_CLASS, EI_DATA, ELFCLASS32, ELFDATA2MSB, EM_ARM, EM_RISCV, ET_DYN, ET_EXEC},
    Elf,
};

use self::fixture::ElfFixtureBuilder;
use crate::{
    ArtifactProfile, ArtifactRequest, ElfClass, ElfReader, Endian, ImageKind, ImageLoader,
    LoadErrorKind, LoadLimits, SliceElfReader,
};
use goblin::elf::program_header::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_TLS,
};

fn riscv64_request() -> ArtifactRequest {
    ArtifactRequest::new(
        ImageKind::StaticPie,
        ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
        LoadLimits::default(),
    )
}

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
fn legacy_loader_rejects_invalid_magic() {
    let mut bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    bytes[0] = 0;
    let mut mapper = crate::MemoryMapper::new(None);

    assert!(crate::load_elf(&bytes, &mut mapper).is_err());
}

#[test]
fn slice_reader_checks_every_requested_range() {
    let reader = SliceElfReader::new(&[1, 2, 3, 4]);
    let mut dst = [0; 2];

    reader.read_exact_at(1, &mut dst).unwrap();
    assert_eq!(dst, [2, 3]);
    assert_eq!(
        reader.read_exact_at(3, &mut dst).unwrap_err().kind(),
        LoadErrorKind::OutOfBounds
    );
    assert_eq!(
        reader.read_exact_at(u64::MAX, &mut dst).unwrap_err().kind(),
        LoadErrorKind::IntegerOverflow
    );
}

#[test]
fn admit_accepts_matching_elf32_and_elf64_headers() {
    let riscv = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    let admitted = ImageLoader::new()
        .admit(SliceElfReader::new(&riscv), riscv64_request())
        .unwrap();
    assert_eq!(admitted.header().class(), ElfClass::Elf64);
    assert_eq!(admitted.file_len(), riscv.len() as u64);

    let arm = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN).build();
    let request = ArtifactRequest::new(
        ImageKind::StaticPie,
        ArtifactProfile::new(ElfClass::Elf32, Endian::Little, EM_ARM),
        LoadLimits::default(),
    );
    let admitted = ImageLoader::new()
        .admit(SliceElfReader::new(&arm), request)
        .unwrap();
    assert_eq!(admitted.header().class(), ElfClass::Elf32);
    assert_eq!(admitted.file_len(), arm.len() as u64);
}

#[test]
fn admit_rejects_truncated_and_mismatched_headers() {
    let truncated = [0; 8];
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&truncated), riscv64_request())
            .unwrap_err()
            .kind(),
        LoadErrorKind::OutOfBounds
    );

    let wrong_class = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_ident(EI_CLASS, ELFCLASS32)
        .build();
    assert!(ImageLoader::new()
        .admit(SliceElfReader::new(&wrong_class), riscv64_request())
        .is_err());

    let wrong_endian = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_ident(EI_DATA, ELFDATA2MSB)
        .build();
    assert!(ImageLoader::new()
        .admit(SliceElfReader::new(&wrong_endian), riscv64_request())
        .is_err());

    let wrong_machine = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_machine(EM_ARM)
        .build();
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&wrong_machine), riscv64_request())
            .unwrap_err()
            .kind(),
        LoadErrorKind::UnsupportedByProfile
    );

    let wrong_type = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_type(ET_EXEC)
        .build();
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&wrong_type), riscv64_request())
            .unwrap_err()
            .kind(),
        LoadErrorKind::UnsupportedByProfile
    );
}

#[test]
fn admit_rejects_program_header_table_outside_the_file() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_program_header_table(64, 1)
        .build();
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap_err()
            .kind(),
        LoadErrorKind::OutOfBounds
    );
}

#[test]
fn admit_enforces_file_and_program_header_limits() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    let file_limit_request = ArtifactRequest::new(
        ImageKind::StaticPie,
        ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
        LoadLimits::new(8, 128),
    );
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&bytes), file_limit_request)
            .unwrap_err()
            .kind(),
        LoadErrorKind::ResourceLimit
    );

    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_program_header_table(64, 1)
        .build();
    let ph_limit_request = ArtifactRequest::new(
        ImageKind::StaticPie,
        ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
        LoadLimits::new(1024, 0),
    );
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&bytes), ph_limit_request)
            .unwrap_err()
            .kind(),
        LoadErrorKind::ResourceLimit
    );
}

#[test]
fn inspect_builds_an_owned_runtime_program_header_view() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x200, PF_R | PF_X, 0x1000)
        .add_program_header(PT_DYNAMIC, 0, 0x2000, 0, 0x40, PF_R | PF_W, 8)
        .add_program_header(PT_GNU_RELRO, 0, 0x2080, 0, 0x20, PF_R, 1)
        .add_program_header(PT_GNU_STACK, 0, 0, 0, 0, PF_R | PF_W, 16)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&bytes), riscv64_request())
        .unwrap();
    let parsed = loader.inspect(&admitted).unwrap();

    assert_eq!(parsed.load_segments().len(), 1);
    assert_eq!(parsed.load_segments()[0].vaddr().get(), 0x1000);
    assert_eq!(parsed.load_segments()[0].memory_size(), 0x200);
    assert_eq!(parsed.dynamic().unwrap().vaddr().get(), 0x2000);
    assert_eq!(parsed.relro().unwrap().start().get(), 0x2080);
    assert_eq!(parsed.stack_policy(), crate::StackPolicy::NonExecutable);
}

#[test]
fn inspect_rejects_file_ranges_outside_the_artifact() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .add_program_header(PT_LOAD, 0x1000, 0, 32, 32, PF_R, 1)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&bytes), riscv64_request())
        .unwrap();

    assert_eq!(
        loader.inspect(&admitted).unwrap_err().kind(),
        LoadErrorKind::OutOfBounds
    );
}

#[test]
fn inspect_rejects_unsupported_runtime_program_headers() {
    for program_type in [PT_INTERP, PT_TLS] {
        let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .add_program_header(program_type, 0, 0, 0, 0, PF_R, 1)
            .build();
        let loader = ImageLoader::new();
        let admitted = loader
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap();
        assert_eq!(
            loader.inspect(&admitted).unwrap_err().kind(),
            LoadErrorKind::UnsupportedByProfile
        );
    }

    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .add_program_header(PT_GNU_STACK, 0, 0, 0, 0, PF_R | PF_W | PF_X, 16)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&bytes), riscv64_request())
        .unwrap();
    assert_eq!(
        loader.inspect(&admitted).unwrap_err().kind(),
        LoadErrorKind::UnsupportedByProfile
    );
}

#[test]
fn inspect_rejects_duplicate_singleton_program_headers() {
    for program_type in [PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK] {
        let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .add_program_header(program_type, 0, 0, 0, 0, PF_R, 1)
            .add_program_header(program_type, 0, 0, 0, 0, PF_R, 1)
            .build();
        let loader = ImageLoader::new();
        let admitted = loader
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap();
        assert_eq!(
            loader.inspect(&admitted).unwrap_err().kind(),
            LoadErrorKind::BadElf
        );
    }
}
