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

//! Symbol name lookup within a file-backed image.

use super::{
    failure, plan, Allocator, Fixture, Input, BASE, GNU_HASH_VADDR, PROFILES, STRVA,
    SYSV_HASH_VADDR, TARGET,
};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::TargetAddress,
    profile::{ElfClass, ElfData, LoadLimits, LoadProfile, LoadPurpose},
};
use alloc::{rc::Rc, vec};
use blueos_test_macro::test;
use goblin::elf::{
    dynamic::{DT_GNU_HASH, DT_HASH, DT_NULL, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB},
    section_header::SHN_ABS,
    sym::{STB_WEAK, STT_TLS},
};

const SYMTAB: u64 = 0x2700;
const NAMES: &[u8] = b"\0foo\0bar\0baz\0";

fn fixture(profile: LoadProfile, sysv: bool, gnu: bool) -> Fixture {
    let (size, info, value, width) = match profile.class() {
        ElfClass::Elf32 => (16, 12, 4, 4),
        ElfClass::Elf64 => (24, 4, 8, 8),
    };
    let mut tags = vec![
        (DT_STRTAB, STRVA),
        (DT_STRSZ, NAMES.len() as u64),
        (DT_SYMTAB, SYMTAB),
        (DT_SYMENT, size as u64),
    ];
    if sysv {
        tags.push((DT_HASH, SYSV_HASH_VADDR));
    }
    if gnu {
        tags.push((DT_GNU_HASH, GNU_HASH_VADDR));
    }
    tags.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &tags);
    let names = fixture.file_offset(STRVA);
    fixture.bytes[names..names + NAMES.len()].copy_from_slice(NAMES);

    let symbols = fixture.file_offset(SYMTAB);
    fixture.bytes[symbols..symbols + 6 * size].fill(0);
    for (index, (name, binding_and_type, visibility, section)) in [
        (1, 0x12, 0, 0), // undefined foo
        (1, 0x12, 2, 1), // hidden foo
        (5, 0x11, 0, 1), // bar
        (1, 0x12, 0, 1), // foo
        (9, 0x21, 3, 1), // weak, protected baz
    ]
    .into_iter()
    .enumerate()
    {
        let index = index + 1;
        let entry = symbols + index * size;
        fixture.number(entry, name, 4);
        fixture.number(entry + value, index as u64 * 16, width);
        fixture.number(entry + info, binding_and_type, 1);
        fixture.number(entry + info + 1, visibility, 1);
        fixture.number(entry + info + 2, section, 2);
    }

    if sysv {
        let file = fixture.file_offset(SYSV_HASH_VADDR);
        // Bucket zero: bar -> baz. Bucket one: the three foo records.
        for (index, word) in [2, 6, 3, 1, 0, 2, 4, 5, 0, 0].into_iter().enumerate() {
            fixture.number(file + index * 4, word, 4);
        }
    }
    if gnu {
        let file = fixture.file_offset(GNU_HASH_VADDR);
        for (index, word) in [1, 3, 2, 5].into_iter().enumerate() {
            fixture.number(file + index * 4, word, 4);
        }
        // Bloom bits for foo, bar, and baz, with bas as a false positive.
        let bloom = match profile.class() {
            ElfClass::Elf32 => [0x1000_0244, 0x0c00_0020],
            ElfClass::Elf64 => [0x0c00_0000_1000_0220, 0x44],
        };
        for (index, word) in bloom.into_iter().enumerate() {
            fixture.number(file + 16 + width * index, word, width);
        }
        for (index, word) in [3, 0x0b88_60ba, 0x0b88_7388, 0x0b88_60c3]
            .into_iter()
            .enumerate()
        {
            fixture.number(file + 16 + 2 * width + index * 4, word, 4);
        }
    }
    fixture
}

#[test]
fn symbol_lookup_resolves_only_matching_visible_definitions() {
    for base in PROFILES {
        for endian in [ElfData::Little, ElfData::Big] {
            let profile = LoadProfile::new(
                base.class(),
                endian,
                base.machine(),
                base.header_flags(),
                base.entry_mode(),
            );
            for (sysv, gnu) in [(true, false), (false, true), (true, true)] {
                let fixture = fixture(profile, sysv, gnu);
                let image = plan(
                    &fixture,
                    LoadPurpose::Executable,
                    LoadLimits::DEFAULT,
                    Rc::default(),
                )
                .unwrap();
                let reader = Input {
                    fixture: &fixture,
                    state: Rc::default(),
                };
                let table = image
                    .dynamic()
                    .unwrap()
                    .symbol_table(&reader, image.segments(), profile.class(), endian)
                    .unwrap()
                    .unwrap();
                for (name, value) in [(b"bar", 48), (b"foo", 64), (b"baz", 80)] {
                    assert_eq!(
                        table.lookup_export(name, 16).unwrap().unwrap().value(),
                        value
                    );
                }
                // GNU hashes of bar and bas differ only in the low chain-end bit.
                assert!(table.lookup_export(b"bas", 16).unwrap().is_none());
            }
        }
    }
}

#[test]
fn sysv_lookup_stops_at_the_match_and_bounds_a_miss() {
    let profile = LoadProfile::riscv64();
    for next in [4, 6] {
        let mut fixture = fixture(profile, true, false);
        let file = fixture.file_offset(SYSV_HASH_VADDR);
        fixture.number(file + (2 + 2 + 4) * 4, next, 4);
        let image = plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            Rc::default(),
        )
        .unwrap();
        let reader = Input {
            fixture: &fixture,
            state: Rc::default(),
        };
        let table = image
            .dynamic()
            .unwrap()
            .symbol_table(&reader, image.segments(), profile.class(), profile.endian())
            .unwrap()
            .unwrap();
        assert_eq!(
            table.lookup_export(b"foo", 16).unwrap().unwrap().value(),
            64
        );
        // A miss in the same bucket reaches the cycle or out-of-range index.
        let error = failure(table.lookup_export(b"foq", 16));
        assert_eq!(error.kind(), LoadErrorKind::BadElf);
        assert!(matches!(
            error.context(),
            ErrorContext::DynamicTag {
                tag: DT_HASH,
                value: SYSV_HASH_VADDR
            }
        ));
    }
}

#[test]
fn dual_hash_lookup_does_not_fall_back_on_gnu_miss() {
    let profile = LoadProfile::riscv64();
    let mut fixture = fixture(profile, true, true);
    let file = fixture.file_offset(GNU_HASH_VADDR);
    fixture.number(file + 16, 0, 8);
    let image = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        Rc::default(),
    )
    .unwrap();
    let reader = Input {
        fixture: &fixture,
        state: Rc::default(),
    };
    let table = image
        .dynamic()
        .unwrap()
        .symbol_table(&reader, image.segments(), profile.class(), profile.endian())
        .unwrap()
        .unwrap();
    assert!(table.lookup_export(b"foo", 16).unwrap().is_none());
}

#[test]
fn dual_hash_lookup_uses_gnu_chain_order() {
    let profile = LoadProfile::riscv64();
    let mut fixture = fixture(profile, true, true);
    // Rename symbol 3 from bar to foo. GNU visits it before symbol 4.
    let symbols = fixture.file_offset(SYMTAB);
    fixture.number(symbols + 3 * 24, 1, 4);
    let gnu = fixture.file_offset(GNU_HASH_VADDR);
    fixture.number(gnu + 16 + 2 * 8 + 4, 0x0b88_7388, 4);

    // SysV bucket zero holds baz. Bucket one visits symbol 4 before symbol 3.
    let sysv = fixture.file_offset(SYSV_HASH_VADDR);
    for (index, word) in [2, 6, 5, 1, 0, 2, 4, 0, 3, 0].into_iter().enumerate() {
        fixture.number(sysv + index * 4, word, 4);
    }
    let image = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        Rc::default(),
    )
    .unwrap();
    let reader = Input {
        fixture: &fixture,
        state: Rc::default(),
    };
    let table = image
        .dynamic()
        .unwrap()
        .symbol_table(&reader, image.segments(), profile.class(), profile.endian())
        .unwrap()
        .unwrap();
    let reads_before_lookup = reader.state.dynamic_reads.get();
    assert_eq!(
        table.lookup_export(b"foo", 16).unwrap().unwrap().value(),
        48
    );
    // The first hit needs one read each for the bloom word, bucket, chain word, symbol and name.
    assert_eq!(reader.state.dynamic_reads.get() - reads_before_lookup, 5);
}

#[test]
fn symbol_addresses_use_the_defining_images_mapping() {
    let profile = LoadProfile::riscv64();
    let mut fixture = fixture(profile, true, false);
    let symbols = fixture.file_offset(SYMTAB);
    fixture.ph(1, 4, 0xa00); // Extend the RW segment with BSS at 0x2900.
    fixture.number(symbols + 3 * 24 + 8, 0x2908, 8); // bar in BSS
    fixture.number(symbols + 4 * 24 + 8, BASE + 0x40, 8); // foo in text
    fixture.number(symbols + 5 * 24 + 6, u64::from(SHN_ABS), 2); // absolute baz

    let state = Rc::default();
    let planned = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        Rc::clone(&state),
    )
    .unwrap();
    let reader = Input {
        fixture: &fixture,
        state: Rc::clone(&state),
    };
    let table = planned
        .dynamic()
        .unwrap()
        .symbol_table(
            &reader,
            planned.segments(),
            profile.class(),
            profile.endian(),
        )
        .unwrap()
        .unwrap();
    let base = 0x800; // Deliberately below the ELF link address.
    let image = planned
        .allocate(Allocator {
            state: Rc::clone(&state),
            base,
        })
        .unwrap()
        .map()
        .unwrap()
        .decode()
        .unwrap();
    for (name, expected) in [(b"foo", base + 0x40), (b"bar", base + 0x1908), (b"baz", 80)] {
        let symbol = table.lookup_export(name, 16).unwrap().unwrap();
        assert_eq!(
            image.symbol_address(&symbol).unwrap(),
            Some(TargetAddress::new(expected))
        );
    }
    assert_eq!(image.symbol_address(&table.read(1).unwrap()).unwrap(), None);
    assert_eq!(state.live.get(), 1);
    drop(image);
    assert_eq!(state.live.get(), 0);
}

#[test]
fn symbol_addresses_check_spans_permissions_and_profile() {
    let profile = LoadProfile::riscv64();
    let mut fixture = fixture(profile, false, true);
    let symbols = fixture.file_offset(SYMTAB);
    fixture.number(symbols + 2 * 24 + 8, TARGET, 8); // function in RW memory
    fixture.number(symbols + 3 * 24 + 8, 0x28ff, 8);
    fixture.number(symbols + 3 * 24 + 16, 2, 8); // object straddles segment end
    fixture.number(symbols + 4 * 24 + 8, u64::MAX, 8); // symbol range overflows
    fixture.number(
        symbols + 5 * 24 + 4,
        u64::from((STB_WEAK << 4) | STT_TLS),
        1,
    );

    let planned = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        Rc::default(),
    )
    .unwrap();
    let reader = Input {
        fixture: &fixture,
        state: Rc::default(),
    };
    let table = planned
        .dynamic()
        .unwrap()
        .symbol_table(
            &reader,
            planned.segments(),
            profile.class(),
            profile.endian(),
        )
        .unwrap()
        .unwrap();
    let image = planned
        .allocate(Allocator {
            state: Rc::default(),
            base: 0x8000,
        })
        .unwrap()
        .map()
        .unwrap()
        .decode()
        .unwrap();
    for (index, kind) in [
        (2, LoadErrorKind::PermissionConflict),
        (3, LoadErrorKind::OutOfBounds),
        (4, LoadErrorKind::IntegerOverflow),
        (5, LoadErrorKind::UnsupportedByProfile),
    ] {
        let error = failure(image.symbol_address(&table.read(index).unwrap()));
        assert_eq!(error.kind(), kind);
    }
}
