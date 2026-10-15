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

use alloc::vec::Vec;
use blueos_test_macro::test;
use core::cell::Cell;
use goblin::elf::{
    header::{
        EI_ABIVERSION, EI_CLASS, EI_DATA, EI_OSABI, EI_VERSION, ELFDATA2MSB, EM_AARCH64, EM_ARM,
        EM_RISCV, ET_DYN, ET_EXEC, ET_REL,
    },
    program_header::{
        PF_R, PF_W, PF_X, PT_ARM_EXIDX, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD,
        PT_NOTE, PT_NULL, PT_PHDR, PT_TLS,
    },
};

use super::fixture::{ElfFixtureBuilder, ProgramHeaderFixture, SliceElfReader};
use crate::{
    error::{ErrorContext, HeaderField, LimitKind, LoadErrorKind, LoadStage, ProgramHeaderField},
    image::ImageLoader,
    memory::{address::TargetAddress, MemoryPermissions},
    profile::{
        ElfClass, ElfData, ElfMachine, LoadLimits, LoadProfile, LoadRequest, ProgramHeaderPolicy,
    },
    reader::ElfReader,
    LoadError, LoadResult,
};

const PROFILES: [LoadProfile; 5] = [
    LoadProfile::arm_thumb_soft_float(),
    LoadProfile::arm_thumb_hard_float(),
    LoadProfile::riscv32(),
    LoadProfile::riscv64(),
    LoadProfile::aarch64(),
];

fn fixture(profile: LoadProfile, elf_type: u16) -> ElfFixtureBuilder {
    let machine = match profile.machine() {
        ElfMachine::Arm => EM_ARM,
        ElfMachine::Riscv => EM_RISCV,
        ElfMachine::Aarch64 => EM_AARCH64,
        ElfMachine::Other(machine) => machine,
    };
    let builder = match profile.class() {
        ElfClass::Elf32 => ElfFixtureBuilder::elf32(machine, elf_type),
        ElfClass::Elf64 => ElfFixtureBuilder::elf64(machine, elf_type),
    };
    builder
        .with_flags(if profile.machine() == ElfMachine::Arm {
            if profile.header_flags().accepts(0x0500_0400) {
                0x0500_0400
            } else {
                0x0500_0200
            }
        } else {
            0
        })
        .with_entry(0x1000)
}

fn header_limits(max_file_len: u64, max_program_headers: u16) -> LoadLimits {
    LoadLimits::new(
        max_file_len,
        max_program_headers,
        32,
        64 * 1024 * 1024,
        1024 * 1024 * 1024,
        1024,
        1024 * 1024,
        64 * 1024 * 1024,
        64 * 1024 * 1024,
        64 * 1024 * 1024,
        4096,
        4096,
    )
}

fn loader(bytes: &[u8], profile: LoadProfile) -> ImageLoader<SliceElfReader<'_>> {
    ImageLoader::new(
        SliceElfReader::new(bytes),
        LoadRequest::new(profile, LoadLimits::DEFAULT),
    )
}

fn failure<T>(result: LoadResult<T>) -> LoadError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("invalid ELF accepted"),
    }
}

fn assert_error(error: &LoadError, stage: LoadStage, kind: LoadErrorKind) {
    assert_eq!(error.stage(), Some(stage), "{error:?}");
    assert_eq!(error.kind(), kind, "{error:?}");
}

fn assert_header_error(
    bytes: &[u8],
    profile: LoadProfile,
    kind: LoadErrorKind,
    expected: HeaderField,
) {
    let error = failure(loader(bytes, profile).admit());
    assert_error(&error, LoadStage::Admit, kind);
    assert!(
        matches!(error.context(), ErrorContext::HeaderField { field, .. } if *field == expected),
        "{error:?}"
    );
}

#[test]
fn admission_accepts_dyn_and_exec_for_all_profiles() {
    for profile in PROFILES {
        for elf_type in [ET_DYN, ET_EXEC] {
            let bytes = fixture(profile, elf_type).with_entry(0x8123_4560).build();
            let admitted = loader(&bytes, profile).admit().unwrap();
            let header = admitted.header();
            assert_eq!(header.class(), profile.class());
            assert_eq!(header.endian(), profile.endian());
            assert_eq!(header.machine(), profile.machine());
            assert_eq!(u64::from(header.r#type()), u64::from(elf_type));
            assert_eq!(header.entry(), 0x8123_4560);
            assert_eq!(header.program_header_count(), 0);
            assert!(admitted.inspect().is_ok());
        }
    }
}

#[test]
fn admission_reports_invalid_ident_fields() {
    for (offset, value, kind, field) in [
        (0, 0, LoadErrorKind::BadElf, HeaderField::Magic),
        (EI_CLASS, 0, LoadErrorKind::BadElf, HeaderField::Class),
        (EI_DATA, 0, LoadErrorKind::BadElf, HeaderField::Endian),
        (EI_VERSION, 0, LoadErrorKind::BadElf, HeaderField::Version),
        (
            EI_OSABI,
            3,
            LoadErrorKind::UnsupportedByProfile,
            HeaderField::OsAbi,
        ),
        (
            EI_ABIVERSION,
            1,
            LoadErrorKind::UnsupportedByProfile,
            HeaderField::AbiVersion,
        ),
    ] {
        let mut bytes = fixture(LoadProfile::riscv64(), ET_DYN).build();
        bytes[offset] = value;
        assert_header_error(&bytes, LoadProfile::riscv64(), kind, field);
    }
}

#[test]
fn admission_rejects_truncated_ident_and_headers() {
    for profile in PROFILES {
        let bytes = fixture(profile, ET_DYN).build();
        for len in [0, 15, 16, bytes.len() - 1] {
            let error = failure(loader(&bytes[..len], profile).admit());
            assert_error(&error, LoadStage::Admit, LoadErrorKind::OutOfBounds);
            assert!(
                matches!(error.context(), ErrorContext::FileRange { offset: 0, file_len, .. } if *file_len == len as u64)
            );
        }
    }
}

#[test]
fn admission_rejects_extended_program_header_numbering() {
    for profile in PROFILES {
        let mut bytes = fixture(profile, ET_DYN).build();
        let count_offset = if profile.class() == ElfClass::Elf32 {
            44
        } else {
            56
        };
        bytes[count_offset..count_offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        // Even a permissive count limit must not interpret PN_XNUM literally.
        let request = LoadRequest::new(profile, header_limits(u64::MAX, u16::MAX));
        let error = failure(ImageLoader::new(SliceElfReader::new(&bytes), request).admit());
        assert_error(
            &error,
            LoadStage::Admit,
            LoadErrorKind::UnsupportedByProfile,
        );
        assert!(matches!(
            error.context(),
            ErrorContext::HeaderField {
                field: HeaderField::ProgramHeaderCount,
                value: 65535
            }
        ));
    }
}

#[test]
fn admission_checks_version_and_structure_sizes_for_both_classes() {
    for profile in [LoadProfile::riscv32(), LoadProfile::riscv64()] {
        let size_offset = if profile.class() == ElfClass::Elf32 {
            40
        } else {
            52
        };
        for (offset, field) in [
            (20, HeaderField::Version),
            (size_offset, HeaderField::HeaderSize),
            (size_offset + 2, HeaderField::ProgramHeaderSize),
        ] {
            let mut bytes = fixture(profile, ET_DYN).build();
            bytes[offset] = 0;
            assert_header_error(&bytes, profile, LoadErrorKind::BadElf, field);
        }
    }
}

#[test]
fn admission_rejects_mismatched_class_machine_and_type() {
    let bytes = fixture(LoadProfile::riscv32(), ET_DYN).build();
    assert_header_error(
        &bytes,
        LoadProfile::riscv64(),
        LoadErrorKind::UnsupportedByProfile,
        HeaderField::Class,
    );
    let bytes = fixture(LoadProfile::riscv64(), ET_DYN).build();
    assert_header_error(
        &bytes,
        LoadProfile::aarch64(),
        LoadErrorKind::UnsupportedByProfile,
        HeaderField::Machine,
    );
    let mut bytes = fixture(LoadProfile::aarch64(), ET_DYN).build();
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    assert_header_error(
        &bytes,
        LoadProfile::aarch64(),
        LoadErrorKind::UnsupportedByProfile,
        HeaderField::Machine,
    );
    let bytes = fixture(LoadProfile::riscv64(), ET_REL).build();
    assert_header_error(
        &bytes,
        LoadProfile::riscv64(),
        LoadErrorKind::UnsupportedByProfile,
        HeaderField::Type,
    );
}

#[test]
fn admission_applies_the_machine_specific_flags_policy() {
    for profile in PROFILES {
        let rejected: &[u32] = if profile == LoadProfile::aarch64() {
            &[1, u32::MAX]
        } else {
            &[2, 4, 6, 8, 9]
        };
        for &flags in rejected {
            let bytes = fixture(profile, ET_DYN).with_flags(flags).build();
            assert_header_error(
                &bytes,
                profile,
                LoadErrorKind::UnsupportedByProfile,
                HeaderField::Flags,
            );
        }
    }
    for profile in [LoadProfile::riscv32(), LoadProfile::riscv64()] {
        let bytes = fixture(profile, ET_DYN).with_flags(1).build();
        assert_eq!(loader(&bytes, profile).admit().unwrap().header().flags(), 1);
    }
}

/// Change numeric fields of this one-program-header fixture to big endian.
fn big_endian(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[EI_DATA] = ELFDATA2MSB;
    let is32 = bytes[EI_CLASS] == 1;
    let fields: &[(usize, usize)] = if is32 {
        &[
            (16, 2),
            (18, 2),
            (20, 4),
            (24, 4),
            (28, 4),
            (32, 4),
            (36, 4),
            (40, 2),
            (42, 2),
            (44, 2),
            (46, 2),
            (48, 2),
            (50, 2),
        ]
    } else {
        &[
            (16, 2),
            (18, 2),
            (20, 4),
            (24, 8),
            (32, 8),
            (40, 8),
            (48, 4),
            (52, 2),
            (54, 2),
            (56, 2),
            (58, 2),
            (60, 2),
            (62, 2),
        ]
    };
    for &(offset, size) in fields {
        bytes[offset..offset + size].reverse();
    }
    if is32 {
        for field in bytes[52..].chunks_exact_mut(4) {
            field.reverse();
        }
    } else {
        bytes[64..68].reverse();
        bytes[68..72].reverse();
        for field in bytes[72..].chunks_exact_mut(8) {
            field.reverse();
        }
    }
    bytes
}

#[test]
fn endian_decoding_is_independent_of_the_native_profiles() {
    for native in [LoadProfile::riscv32(), LoadProfile::riscv64()] {
        let bytes = big_endian(
            fixture(native, ET_DYN)
                .with_entry(0x1234_5678)
                .with_program_header(ProgramHeaderFixture::load())
                .build(),
        );
        assert_header_error(
            &bytes,
            native,
            LoadErrorKind::UnsupportedByProfile,
            HeaderField::Endian,
        );
        let profile = LoadProfile::new(
            native.class(),
            ElfData::Big,
            native.machine(),
            native.header_flags(),
            native.entry_mode(),
        );
        let admitted = loader(&bytes, profile).admit().unwrap();
        assert_eq!(admitted.header().entry(), 0x1234_5678);
        let image = admitted.inspect().unwrap();
        let (_, _, segments) = image.scan_parts();
        assert_eq!(segments[0].vaddr().get(), 0x1000);
        assert_eq!(segments[0].file_range().len(), 4);
        assert!(segments[0].permissions().contains(MemoryPermissions::READ));
        assert!(segments[0]
            .permissions()
            .contains(MemoryPermissions::EXECUTE));
        assert!(!segments[0].permissions().contains(MemoryPermissions::WRITE));
    }
}

struct ProbeReader<'a> {
    bytes: &'a [u8],
    file_len: u64,
    reads: &'a Cell<usize>,
    fail_at: Option<usize>,
}

impl ElfReader for ProbeReader<'_> {
    fn len(&self) -> LoadResult<u64> {
        if self.fail_at == Some(0) {
            return Err(LoadError::new(LoadErrorKind::Io, ErrorContext::None));
        }
        Ok(self.file_len)
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let call = self.reads.get() + 1;
        self.reads.set(call);
        if self.fail_at == Some(call) {
            return Err(LoadError::new(
                LoadErrorKind::Io,
                ErrorContext::FileRange {
                    offset,
                    len: dst.len() as u64,
                    file_len: self.file_len,
                },
            ));
        }
        SliceElfReader::new(self.bytes).read_exact_at(offset, dst)
    }
}

#[test]
fn file_and_header_count_limits_precede_further_reads() {
    let profile = LoadProfile::riscv64();
    let bytes = fixture(profile, ET_DYN)
        .with_program_header(ProgramHeaderFixture::load())
        .build();
    for (limits, expected_reads, resource) in [
        (header_limits(0, 128), 0, LimitKind::FileLength),
        (header_limits(1024, 0), 2, LimitKind::ProgramHeaderCount),
    ] {
        let reads = Cell::new(0);
        let reader = ProbeReader {
            bytes: &bytes,
            file_len: bytes.len() as u64,
            reads: &reads,
            fail_at: None,
        };
        let error = failure(ImageLoader::new(reader, LoadRequest::new(profile, limits)).admit());
        assert_error(&error, LoadStage::Admit, LoadErrorKind::ResourceLimit);
        assert_eq!(reads.get(), expected_reads);
        assert!(matches!(
            (error.context(), resource),
            (
                ErrorContext::Limit {
                    resource: LimitKind::FileLength,
                    actual: 120,
                    maximum: 0
                },
                LimitKind::FileLength
            ) | (
                ErrorContext::Limit {
                    resource: LimitKind::ProgramHeaderCount,
                    actual: 1,
                    maximum: 0
                },
                LimitKind::ProgramHeaderCount
            )
        ));
    }
    let exact_limits = header_limits(bytes.len() as u64, 1);
    ImageLoader::new(
        SliceElfReader::new(&bytes),
        LoadRequest::new(profile, exact_limits),
    )
    .admit()
    .unwrap()
    .inspect()
    .unwrap();
}

#[test]
fn admission_rejects_overlapping_truncated_and_overflowing_header_tables() {
    let profile = LoadProfile::riscv64();
    for (offset, file_len, kind) in [
        (63, 120, LoadErrorKind::BadElf),
        (100, 120, LoadErrorKind::OutOfBounds),
        (u64::MAX - 4, u64::MAX, LoadErrorKind::IntegerOverflow),
    ] {
        let mut bytes = fixture(profile, ET_DYN)
            .with_program_header(ProgramHeaderFixture::load())
            .build();
        bytes[32..40].copy_from_slice(&offset.to_le_bytes());
        let reads = Cell::new(0);
        let reader = ProbeReader {
            bytes: &bytes,
            file_len,
            reads: &reads,
            fail_at: None,
        };
        let error = failure(
            ImageLoader::new(
                reader,
                LoadRequest::new(profile, header_limits(u64::MAX, 128)),
            )
            .admit(),
        );
        assert_error(&error, LoadStage::Admit, kind);
        assert_eq!(reads.get(), 2); // No program header is read after an invalid table extent.
    }
    let mut bytes = fixture(LoadProfile::riscv32(), ET_DYN)
        .with_program_header(ProgramHeaderFixture::load())
        .build();
    bytes.pop();
    let error = failure(loader(&bytes, LoadProfile::riscv32()).admit());
    assert_error(&error, LoadStage::Admit, LoadErrorKind::OutOfBounds);
}

#[test]
fn reader_failures_keep_their_context_and_acquire_the_correct_stage() {
    let profile = LoadProfile::riscv64();
    let bytes = fixture(profile, ET_DYN)
        .with_program_header(ProgramHeaderFixture::load())
        .build();
    for call in 0..=3 {
        let reads = Cell::new(0);
        let reader = ProbeReader {
            bytes: &bytes,
            file_len: bytes.len() as u64,
            reads: &reads,
            fail_at: Some(call),
        };
        let error = failure(
            ImageLoader::new(reader, LoadRequest::new(profile, LoadLimits::DEFAULT))
                .admit()
                .and_then(|image| image.inspect()),
        );
        assert_error(
            &error,
            if call == 3 {
                LoadStage::Inspect
            } else {
                LoadStage::Admit
            },
            LoadErrorKind::Io,
        );
        if call != 0 {
            let expected_offset = if call == 3 { 64 } else { 0 };
            assert!(
                matches!(error.context(), ErrorContext::FileRange { offset, file_len: 120, .. } if *offset == expected_offset)
            );
        }
        assert_eq!(reads.get(), call);
    }
}

#[test]
fn inspection_reports_the_rejected_header_index_and_type() {
    for profile in PROFILES {
        for kind in [PT_INTERP, PT_TLS, 0x6000_0042] {
            let bytes = fixture(profile, ET_DYN)
                .with_program_header(ProgramHeaderFixture {
                    kind: PT_NOTE,
                    ..ProgramHeaderFixture::load()
                })
                .with_program_header(ProgramHeaderFixture {
                    kind,
                    ..ProgramHeaderFixture::load()
                })
                .build();
            let error = failure(loader(&bytes, profile).admit().unwrap().inspect());
            assert_error(
                &error,
                LoadStage::Inspect,
                LoadErrorKind::UnsupportedByProfile,
            );
            assert!(
                matches!(error.context(), ErrorContext::ProgramHeader { index: 1, field, value }
                if *value == u64::from(kind) && matches!((kind, field),
                    (PT_INTERP, ProgramHeaderField::UnsupportedInterpreter)
                    | (PT_TLS, ProgramHeaderField::UnsupportedTls)
                    | (0x6000_0042, ProgramHeaderField::Type)))
            );
        }
    }
}

#[test]
fn inspection_uses_the_callers_program_header_whitelist() {
    const ALLOWED: &[u32] = &[PT_NOTE, PT_INTERP, PT_TLS, 0x6000_0042];
    for base in PROFILES {
        let profile = base.with_program_header_policy(ProgramHeaderPolicy::new(ALLOWED, false));
        for &kind in ALLOWED {
            let bytes = fixture(profile, ET_DYN)
                .with_program_header(ProgramHeaderFixture {
                    kind,
                    ..ProgramHeaderFixture::load()
                })
                .build();
            assert!(loader(&bytes, profile).admit().unwrap().inspect().is_ok());
        }
        let bytes = fixture(profile, ET_DYN)
            .with_program_header(ProgramHeaderFixture::load())
            .build();
        let error = failure(loader(&bytes, profile).admit().unwrap().inspect());
        assert_error(
            &error,
            LoadStage::Inspect,
            LoadErrorKind::UnsupportedByProfile,
        );
        assert!(
            matches!(error.context(), ErrorContext::ProgramHeader { index: 0, field: ProgramHeaderField::Type, value }
            if *value == u64::from(PT_LOAD))
        );
    }
}

#[test]
fn additional_program_headers_retain_defaults_and_can_be_replaced_or_cleared() {
    for base in PROFILES {
        let mut profile = base.with_additional_program_headers(&[PT_TLS]);
        let bytes = fixture(profile, ET_DYN)
            .with_program_header(ProgramHeaderFixture::load())
            .with_program_header(ProgramHeaderFixture {
                kind: PT_TLS,
                ..ProgramHeaderFixture::load()
            })
            .build();
        assert!(loader(&bytes, profile).admit().unwrap().inspect().is_ok());
        for types in [&[PT_INTERP][..], &[][..]] {
            profile.set_additional_program_headers(types);
            let error = failure(loader(&bytes, profile).admit().unwrap().inspect());
            assert_error(
                &error,
                LoadStage::Inspect,
                LoadErrorKind::UnsupportedByProfile,
            );
            assert!(matches!(
                error.context(),
                ErrorContext::ProgramHeader {
                    index: 1,
                    field: ProgramHeaderField::UnsupportedTls,
                    ..
                }
            ));
        }
        assert!(loader(&bytes, base).admit().unwrap().inspect().is_err());
    }
}

#[test]
fn additional_program_headers_preserve_custom_base_and_stack_policy() {
    for base in PROFILES {
        let profile = base
            .with_program_header_policy(ProgramHeaderPolicy::new(&[PT_GNU_STACK], true))
            .with_additional_program_headers(&[PT_TLS]);
        let bytes = fixture(profile, ET_DYN)
            .with_program_header(ProgramHeaderFixture {
                kind: PT_GNU_STACK,
                flags: PF_R | PF_W | PF_X,
                ..ProgramHeaderFixture::load()
            })
            .with_program_header(ProgramHeaderFixture {
                kind: PT_TLS,
                ..ProgramHeaderFixture::load()
            })
            .build();
        assert!(loader(&bytes, profile).admit().unwrap().inspect().is_ok());
        let bytes = fixture(profile, ET_DYN)
            .with_program_header(ProgramHeaderFixture::load())
            .build();
        let error = failure(loader(&bytes, profile).admit().unwrap().inspect());
        assert_error(
            &error,
            LoadStage::Inspect,
            LoadErrorKind::UnsupportedByProfile,
        );
    }
}

#[test]
fn inspection_uses_the_callers_executable_stack_policy() {
    for base in PROFILES {
        for allowed in [false, true] {
            let profile = base.with_program_header_policy(
                base.program_header_policy().with_executable_stack(allowed),
            );
            let bytes = fixture(profile, ET_DYN)
                .with_program_header(ProgramHeaderFixture {
                    kind: PT_NOTE,
                    ..ProgramHeaderFixture::load()
                })
                .with_program_header(ProgramHeaderFixture {
                    kind: PT_GNU_STACK,
                    flags: PF_R | PF_W | PF_X,
                    ..ProgramHeaderFixture::load()
                })
                .build();
            let result = loader(&bytes, profile).admit().unwrap().inspect();
            if allowed {
                assert!(result.is_ok());
            } else {
                let error = failure(result);
                assert_error(
                    &error,
                    LoadStage::Inspect,
                    LoadErrorKind::UnsupportedByProfile,
                );
                assert!(matches!(
                    error.context(),
                    ErrorContext::ProgramHeader {
                        index: 1,
                        field: ProgramHeaderField::ExecutableStack,
                        value: 7
                    }
                ));
            }
        }
    }
}

#[test]
fn custom_program_header_policies_preserve_structural_checks() {
    for base in PROFILES {
        let profile = base.with_program_header_policy(ProgramHeaderPolicy::new(
            &[PT_LOAD, PT_DYNAMIC, PT_TLS, PT_GNU_STACK],
            true,
        ));
        for (kind, offset, filesz, memsz, expected) in [
            (PT_LOAD, 0, 2, 1, LoadErrorKind::BadElf),
            (PT_DYNAMIC, 0, 2, 1, LoadErrorKind::BadElf),
            (PT_TLS, 0, 2, 1, LoadErrorKind::BadElf),
            (PT_TLS, 0x1000, 4, 4, LoadErrorKind::OutOfBounds),
        ] {
            let bytes = fixture(profile, ET_DYN)
                .with_program_header(ProgramHeaderFixture {
                    kind,
                    offset,
                    filesz,
                    memsz,
                    ..ProgramHeaderFixture::load()
                })
                .build();
            let error = failure(loader(&bytes, profile).admit().unwrap().inspect());
            assert_error(&error, LoadStage::Inspect, expected);
        }
    }
    let profile = LoadProfile::riscv64().with_additional_program_headers(&[PT_TLS]);
    let bytes = fixture(profile, ET_DYN)
        .with_program_header(ProgramHeaderFixture {
            kind: PT_TLS,
            vaddr: TargetAddress::new(u64::MAX),
            memsz: 1,
            filesz: 0,
            ..ProgramHeaderFixture::load()
        })
        .build();
    let error = failure(loader(&bytes, profile).admit().unwrap().inspect());
    assert_error(&error, LoadStage::Inspect, LoadErrorKind::IntegerOverflow);
    assert!(matches!(
        error.context(),
        ErrorContext::ProgramHeader {
            index: 0,
            field: ProgramHeaderField::VirtualRange,
            ..
        }
    ));
}

#[test]
fn inspection_tracks_each_singleton_independently() {
    const KINDS: [u32; 9] = [
        PT_DYNAMIC,
        PT_LOAD,
        PT_PHDR,
        PT_NOTE,
        PT_GNU_RELRO,
        PT_NULL,
        PT_GNU_STACK,
        PT_INTERP,
        PT_TLS,
    ];
    for base in PROFILES {
        let profile = base.with_additional_program_headers(&[PT_INTERP, PT_TLS]);
        let (header_size, entry_size, dynamic_size) = match profile.class() {
            ElfClass::Elf32 => (52, 32, 8),
            ElfClass::Elf64 => (64, 56, 16),
        };
        for duplicate in [
            None,
            Some(PT_DYNAMIC),
            Some(PT_PHDR),
            Some(PT_GNU_RELRO),
            Some(PT_GNU_STACK),
            Some(PT_INTERP),
            Some(PT_TLS),
        ] {
            let mut builder = fixture(profile, ET_DYN);
            for kind in KINDS {
                builder = builder.with_program_header(ProgramHeaderFixture {
                    kind,
                    flags: PF_R,
                    offset: if kind == PT_DYNAMIC {
                        header_size + entry_size * KINDS.len() as u64
                    } else {
                        0
                    },
                    filesz: if kind == PT_DYNAMIC { dynamic_size } else { 0 },
                    memsz: dynamic_size,
                    ..ProgramHeaderFixture::load()
                });
            }
            if let Some(kind) = duplicate {
                builder = builder.with_program_header(ProgramHeaderFixture {
                    kind,
                    ..ProgramHeaderFixture::load()
                });
            }
            let mut bytes = builder.build();
            bytes.extend_from_slice(&[0; 16]); // A terminating DT_NULL for the unique case.
            let result = loader(&bytes, profile).admit().unwrap().inspect();
            if let Some(kind) = duplicate {
                let error = failure(result);
                assert_error(&error, LoadStage::Inspect, LoadErrorKind::BadElf);
                assert!(
                    matches!(error.context(), ErrorContext::ProgramHeader { index: 9, field, value }
                    if *value == u64::from(kind) && matches!((kind, field),
                        (PT_DYNAMIC, ProgramHeaderField::DuplicateDynamic)
                        | (PT_PHDR, ProgramHeaderField::DuplicatePhdr)
                        | (PT_GNU_RELRO, ProgramHeaderField::DuplicateRelro)
                        | (PT_GNU_STACK, ProgramHeaderField::DuplicateStack)
                        | (PT_INTERP, ProgramHeaderField::DuplicateInterpreter)
                        | (PT_TLS, ProgramHeaderField::DuplicateTls)))
                );
            } else {
                assert!(result.is_ok(), "{:?}", result.err());
            }
        }
    }
}

#[test]
fn processor_header_defaults_are_retained_when_extending_a_profile() {
    for base in PROFILES {
        let profile = base.with_additional_program_headers(&[PT_TLS]);
        for kind in [PT_ARM_EXIDX, 0x7000_0003] {
            let bytes = fixture(profile, ET_DYN)
                .with_program_header(ProgramHeaderFixture {
                    kind,
                    ..ProgramHeaderFixture::load()
                })
                .build();
            let result = loader(&bytes, profile).admit().unwrap().inspect();
            let accepted = matches!(
                (profile.machine(), kind),
                (ElfMachine::Arm, PT_ARM_EXIDX) | (ElfMachine::Riscv, 0x7000_0003)
            );
            assert_eq!(result.is_ok(), accepted);
        }
    }
}

#[test]
fn inspection_ignores_undefined_null_header_fields() {
    let profile = LoadProfile::riscv64();
    let bytes = fixture(profile, ET_DYN)
        .with_program_header(ProgramHeaderFixture {
            kind: PT_NULL,
            offset: u64::MAX,
            vaddr: TargetAddress::new(u64::MAX),
            filesz: u64::MAX,
            memsz: u64::MAX,
            ..ProgramHeaderFixture::load()
        })
        .build();
    assert!(loader(&bytes, profile).admit().unwrap().inspect().is_ok());
}
