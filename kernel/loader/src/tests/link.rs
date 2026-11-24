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

//! Eager linking through the public dependency plan and image mapping interfaces.

use alloc::{rc::Rc, vec::Vec};

use blueos_test_macro::test;
use goblin::elf::{
    dynamic::{
        DF_1_PIE, DT_BIND_NOW, DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS_1, DT_HASH,
        DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTREL,
        DT_PLTRELSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_RELA, DT_STRSZ, DT_STRTAB, DT_SYMENT,
        DT_SYMTAB,
    },
    reloc::{
        R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE, R_RISCV_32,
        R_RISCV_64, R_RISCV_COPY, R_RISCV_JUMP_SLOT, R_RISCV_RELATIVE,
    },
    section_header::SHN_UNDEF,
    sym::{
        STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FUNC, STT_OBJECT, STV_DEFAULT, STV_HIDDEN,
        STV_PROTECTED,
    },
};

use super::{
    dependency::{Catalog, Route},
    failure, relocation_size, request, tags, Allocation, Allocator, Fixture, State, BASE, PROFILES,
    RELVA, STRVA, TARGET,
};
use crate::{
    dynamic_linker::{discover, link, LinkedImages},
    error::{ErrorContext, LimitKind, LoadErrorKind, LoadStage},
    memory::{AllocationOffset, ImageLayout, TargetAddress},
    profile::{
        DependencyLimits, ElfClass, ElfMachine, LinkLimits, LoadLimits, LoadProfile, LoadPurpose,
    },
    ImageAllocator, ImageMapping, LoadResult,
};

const SYMBOLS: u64 = 0x2200;
const HASH: u64 = 0x2300;
const PLT: u64 = 0x24c0;
const LIB_DATA: u64 = 0x2700;
const PLT_SLOT: u64 = TARGET + 0x70;
const STRINGS: &[u8] = b"\0a\0b\0func\0data\0weak\0";
const A: u64 = 1;
const B: u64 = 3;
const FUNC: u32 = 5;
const DATA: u32 = 10;
const WEAK: u32 = 15;
const ROUTES: &[Route<'_>] = &[(0, b"a", 1), (0, b"b", 2)];

type SymbolSpec = (u32, u8, u8, u8, u32, u64);
type RelocationSpec = (u64, u32, u32, i64);

fn fixture(
    profile: LoadProfile,
    purpose: LoadPurpose,
    needed: &[u64],
    symbols: &[SymbolSpec],
    relocations: &[RelocationSpec],
    jump: Option<RelocationSpec>,
) -> Fixture {
    let (stride, info, value, width) = match profile.class() {
        ElfClass::Elf32 => (16, 12, 4, 4),
        ElfClass::Elf64 => (24, 4, 8, 8),
    };
    let mut dynamic = Vec::from([
        (DT_SYMTAB, SYMBOLS),
        (DT_SYMENT, stride as u64),
        (DT_STRTAB, STRVA),
        (DT_STRSZ, STRINGS.len() as u64),
        (DT_HASH, HASH),
    ]);
    dynamic.extend(needed.iter().map(|&offset| (DT_NEEDED, offset)));
    if purpose == LoadPurpose::Executable {
        dynamic.push((DT_FLAGS_1, DF_1_PIE));
    }
    if !relocations.is_empty() {
        dynamic.extend(tags(
            profile.class(),
            DT_RELA,
            RELVA,
            relocations.len() as u64,
        ));
    }
    let relocation_size = relocation_size(profile.class(), DT_RELA);
    if jump.is_some() {
        dynamic.extend([
            (DT_JMPREL, PLT),
            (DT_PLTRELSZ, relocation_size),
            (DT_PLTREL, DT_RELA),
            (DT_BIND_NOW, 0),
        ]);
    }
    dynamic.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &dynamic);
    if purpose == LoadPurpose::SharedObject {
        fixture.entry(0);
    }
    let strings = fixture.file_offset(STRVA);
    fixture.bytes[strings..strings + STRINGS.len()].copy_from_slice(STRINGS);
    let start = fixture.file_offset(SYMBOLS);
    fixture.bytes[start..start + (symbols.len() + 1) * stride].fill(0);
    for (index, &(name, binding, kind, visibility, section, address)) in symbols.iter().enumerate()
    {
        let entry = start + (index + 1) * stride;
        fixture.number(entry, u64::from(name), 4);
        fixture.number(entry + info, u64::from((binding << 4) | kind), 1);
        fixture.number(entry + info + 1, u64::from(visibility), 1);
        fixture.number(entry + info + 2, u64::from(section), 2);
        fixture.number(entry + value, address, width);
    }
    let hash = fixture.file_offset(HASH);
    let count = symbols.len() + 1;
    for (index, word) in [1, count as u64, u64::from(!symbols.is_empty()), 0]
        .into_iter()
        .enumerate()
    {
        fixture.number(hash + index * 4, word, 4);
    }
    for index in 1..count {
        let next = if index + 1 == count { 0 } else { index + 1 };
        fixture.number(hash + (index + 3) * 4, next as u64, 4);
    }
    for (index, &(target, symbol, kind, addend)) in relocations.iter().enumerate() {
        fixture.relocation(
            RELVA + index as u64 * relocation_size,
            DT_RELA,
            target,
            symbol,
            kind,
            addend,
        );
    }
    if let Some((target, symbol, kind, addend)) = jump {
        fixture.relocation(PLT, DT_RELA, target, symbol, kind, addend);
    }
    fixture
}

struct DistinctAllocations(Rc<State>);

impl ImageAllocator for DistinctAllocations {
    type Allocation = Allocation;

    fn prepare_image(&mut self, layout: &ImageLayout) -> LoadResult<Self::Allocation> {
        Allocator {
            state: self.0.clone(),
            base: 0x8000 + self.0.prepares.get() as u64 * 0x4000,
        }
        .prepare_image(layout)
    }
}

fn link_fixtures(
    catalog: &mut Catalog<'_>,
    profile: LoadProfile,
    limits: LinkLimits,
) -> LoadResult<LinkedImages<usize, Allocation>> {
    let plan = discover(
        0,
        request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT),
        DependencyLimits::DEFAULT,
        catalog,
    )?;
    link(plan, limits, DistinctAllocations(catalog.state.clone()))
}

fn word(image: &impl ImageMapping, profile: LoadProfile, target: u64) -> u64 {
    let mut bytes = [0; 8];
    let width = match profile.class() {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    };
    image
        .read(AllocationOffset::new(target - BASE), &mut bytes[..width])
        .unwrap();
    u64::from_le_bytes(bytes)
}

fn kinds(profile: LoadProfile) -> (u32, u32, u32) {
    match (profile.machine(), profile.class()) {
        (ElfMachine::Riscv, ElfClass::Elf32) => (R_RISCV_32, R_RISCV_JUMP_SLOT, R_RISCV_RELATIVE),
        (ElfMachine::Riscv, ElfClass::Elf64) => (R_RISCV_64, R_RISCV_JUMP_SLOT, R_RISCV_RELATIVE),
        (ElfMachine::Aarch64, ElfClass::Elf64) => {
            (R_AARCH64_ABS64, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE)
        }
        _ => unreachable!(),
    }
}

fn lifecycle_fixture(
    profile: LoadProfile,
    purpose: LoadPurpose,
    needed: &[u64],
    init: u64,
) -> Fixture {
    const NAMES: &[u8] = b"\0a\0b\0c\0d\0";
    const INIT: u64 = 0x2600;
    const FINI: u64 = 0x2620;
    const PREINIT: u64 = 0x2640;
    let width = match profile.class() {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    };
    let mut dynamic = Vec::from([
        (DT_STRTAB, STRVA),
        (DT_STRSZ, NAMES.len() as u64),
        (DT_INIT, init),
        (DT_INIT_ARRAY, INIT),
        (DT_INIT_ARRAYSZ, width),
        (DT_FINI_ARRAY, FINI),
        (DT_FINI_ARRAYSZ, 2 * width),
        (DT_FINI, BASE + 0x30),
    ]);
    dynamic.extend(needed.iter().map(|&offset| (DT_NEEDED, offset)));
    let mut relocations = Vec::from([
        (INIT, BASE + 0x20),
        (FINI, BASE + 0x40),
        (FINI + width, BASE + 0x50),
    ]);
    if purpose == LoadPurpose::Executable {
        dynamic.extend([
            (DT_PREINIT_ARRAY, PREINIT),
            (DT_PREINIT_ARRAYSZ, width),
            (DT_FLAGS_1, DF_1_PIE),
        ]);
        relocations.push((PREINIT, BASE));
    }
    dynamic.extend(tags(
        profile.class(),
        DT_RELA,
        RELVA,
        relocations.len() as u64,
    ));
    dynamic.push((DT_NULL, 0));

    let mut fixture = Fixture::new(profile, &dynamic);
    if purpose == LoadPurpose::SharedObject {
        fixture.entry(0);
    }
    let strings = fixture.file_offset(STRVA);
    fixture.bytes[strings..strings + NAMES.len()].copy_from_slice(NAMES);
    let (_, _, relative) = kinds(profile);
    for (index, (target, address)) in relocations.into_iter().enumerate() {
        fixture.relocation(
            RELVA + index as u64 * relocation_size(profile.class(), DT_RELA),
            DT_RELA,
            target,
            0,
            relative,
            address as i64,
        );
    }
    fixture
}

#[test]
fn linked_lifecycle_orders_diamond_and_cycle_after_relocation() {
    const C: u64 = 5;
    const D: u64 = 7;
    for profile in PROFILES {
        let exe = LoadPurpose::Executable;
        let dso = LoadPurpose::SharedObject;
        // a and b share c. a and c form a component that depends on d.
        let fixtures = [
            lifecycle_fixture(profile, exe, &[A, B], BASE + 0x10),
            lifecycle_fixture(profile, dso, &[C], BASE + 0x10),
            lifecycle_fixture(profile, dso, &[C, C], BASE + 0x10),
            lifecycle_fixture(profile, dso, &[A, D], BASE + 0x10),
            lifecycle_fixture(profile, dso, &[], BASE + 0x10),
        ];
        let mut catalog = Catalog::new(
            &fixtures,
            &[
                (0, b"a", 1),
                (0, b"b", 2),
                (1, b"c", 3),
                (2, b"c", 3),
                (3, b"a", 1),
                (3, b"d", 4),
            ],
        );
        let linked = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
        let callback = |image: usize, offset| {
            linked.images()[image]
                .allocation()
                .base()
                .checked_add(offset)
                .unwrap()
        };
        let lifecycle = linked.plan_lifecycle().unwrap();
        assert_eq!(lifecycle.preinit(), &[callback(0, 0)]);
        assert!(lifecycle.init().eq([4, 1, 3, 2, 0]
            .into_iter()
            .flat_map(|image| [callback(image, 0x10), callback(image, 0x20)])));
        assert!(lifecycle
            .fini()
            .eq([0, 2, 3, 1, 4].into_iter().flat_map(|image| [
                callback(image, 0x50),
                callback(image, 0x40),
                callback(image, 0x30)
            ])));
        assert_eq!(catalog.state.live.get(), 5);
        drop(linked);
        assert_eq!(catalog.state.live.get(), 0);
    }
}

#[test]
fn linked_lifecycle_reports_invalid_callbacks_with_the_lifecycle_stage() {
    let profile = LoadProfile::riscv64();
    let fixtures = [
        lifecycle_fixture(profile, LoadPurpose::Executable, &[A], BASE + 0x10),
        lifecycle_fixture(profile, LoadPurpose::SharedObject, &[], LIB_DATA),
    ];
    let mut catalog = Catalog::new(&fixtures, ROUTES);
    let linked = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
    let error = failure(linked.plan_lifecycle());
    assert_eq!(error.stage(), Some(LoadStage::Lifecycle));
    assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
    assert!(matches!(
        error.context(),
        ErrorContext::DynamicTag {
            tag: DT_INIT,
            value,
        } if *value == linked.images()[1].allocation().base().get() + LIB_DATA - BASE
    ));
    assert_eq!(catalog.state.live.get(), 2);
}

#[test]
fn link_binds_data_and_eager_plt_in_breadth_first_scope() {
    for profile in PROFILES {
        let (absolute, jump, relative) = kinds(profile);
        let data_kind = if profile.machine() == ElfMachine::Aarch64 {
            R_AARCH64_GLOB_DAT
        } else {
            absolute
        };
        let inputs = [
            fixture(
                profile,
                LoadPurpose::Executable,
                &[A, B],
                &[
                    (FUNC, STB_GLOBAL, STT_FUNC, STV_DEFAULT, SHN_UNDEF, 0),
                    (DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0),
                    (WEAK, STB_WEAK, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0),
                ],
                &[
                    (TARGET, 2, data_kind, 8),
                    (TARGET + 8, 3, absolute, 0),
                    (TARGET + 16, 0, relative, BASE as i64),
                    (TARGET + 24, 0, absolute, 0x3344),
                ],
                Some((PLT_SLOT, 1, jump, 4)),
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[],
                &[
                    (FUNC, STB_WEAK, STT_FUNC, STV_DEFAULT, 1, BASE + 0x10),
                    (DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA),
                ],
                &[],
                None,
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[],
                &[
                    (FUNC, STB_GLOBAL, STT_FUNC, STV_DEFAULT, 1, BASE + 0x20),
                    (DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA + 8),
                ],
                &[],
                None,
            ),
        ];
        let mut catalog = Catalog::new(&inputs, ROUTES);
        let result = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
        let images = result.images();
        let root = images[0].allocation();
        let data = images[1].allocation().base().get() + LIB_DATA - BASE;
        let func = images[1].allocation().base().get() + 0x10;
        let plt_addend = u64::from(profile.machine() == ElfMachine::Aarch64) * 4;
        assert_eq!(word(root, profile, TARGET), data + 8);
        assert_eq!(word(root, profile, TARGET + 8), 0);
        assert_eq!(word(root, profile, TARGET + 16), root.base().get());
        assert_eq!(word(root, profile, TARGET + 24), 0x3344);
        assert_eq!(word(root, profile, PLT_SLOT), func + plt_addend);
        assert_eq!(result.edges().len(), 2);
        assert_eq!(catalog.state.reader_drops.get(), 3);
        assert_eq!(catalog.state.live.get(), 3);
        drop(result);
        assert_eq!(catalog.state.drops.get(), 3);
    }
}

#[test]
fn link_keeps_indexed_references_local_and_preempts_default_definitions() {
    let profile = LoadProfile::riscv64();
    for (binding, visibility, local) in [
        (STB_GLOBAL, STV_DEFAULT, false),
        (STB_GLOBAL, STV_PROTECTED, true),
        (STB_GLOBAL, STV_HIDDEN, true),
        (STB_LOCAL, STV_DEFAULT, true),
    ] {
        let inputs = [
            fixture(
                profile,
                LoadPurpose::Executable,
                &[A],
                &[(DATA, STB_WEAK, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA)],
                &[],
                None,
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[],
                &[(DATA, binding, STT_OBJECT, visibility, 1, LIB_DATA)],
                &[(TARGET, 1, R_RISCV_64, 0)],
                None,
            ),
        ];
        let mut catalog = Catalog::new(&inputs, ROUTES);
        let linked = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
        let images = linked.images();
        let base = images[usize::from(local)].allocation().base().get();
        assert_eq!(
            word(images[1].allocation(), profile, TARGET),
            base + LIB_DATA - BASE
        );
    }
}

#[test]
fn link_rejects_invalid_later_images_before_any_relocation_write() {
    let profile = LoadProfile::riscv64();
    for (section, address, kind, jump, expected) in [
        (
            SHN_UNDEF,
            0,
            R_RISCV_64,
            None,
            LoadErrorKind::UnresolvedSymbol,
        ),
        (
            SHN_UNDEF,
            0,
            R_RISCV_COPY,
            None,
            LoadErrorKind::UnsupportedByProfile,
        ),
        (
            1,
            LIB_DATA,
            R_RISCV_64,
            Some((PLT_SLOT, 1, R_RISCV_JUMP_SLOT, 0)),
            LoadErrorKind::PermissionConflict,
        ),
    ] {
        let inputs = [
            fixture(
                profile,
                LoadPurpose::Executable,
                &[A],
                &[],
                &[(TARGET, 0, R_RISCV_RELATIVE, BASE as i64)],
                None,
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[],
                &[(DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, section, address)],
                &[(TARGET, 1, kind, 0)],
                jump,
            ),
        ];
        let mut catalog = Catalog::new(&inputs, ROUTES);
        let error = failure(link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT));
        assert_eq!(error.stage(), Some(LoadStage::Relocate));
        assert_eq!(error.kind(), expected);
        assert_eq!(catalog.state.live.get(), 0);
        assert_eq!(catalog.state.drops.get(), 2);
        // Two file-backed segments per fixture, copied in 512-byte chunks.
        assert_eq!(catalog.state.writes.get(), 12);
    }
}

#[test]
fn link_checks_closure_relocation_and_probe_budgets() {
    let profile = LoadProfile::aarch64();
    let inputs = [fixture(
        profile,
        LoadPurpose::Executable,
        &[],
        &[(DATA, STB_WEAK, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0)],
        &[(TARGET, 1, R_AARCH64_ABS64, 0)],
        None,
    )];
    for (limits, relocations, prepared) in [
        (LinkLimits::new(0, 1, 256), true, 0),
        (LinkLimits::new(1, 0, 256), false, 1),
    ] {
        let mut catalog = Catalog::new(&inputs, &[]);
        let error = failure(link_fixtures(&mut catalog, profile, limits));
        assert_eq!(error.stage(), Some(LoadStage::Relocate));
        assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
        assert!(matches!(
            (relocations, error.context()),
            (
                true,
                ErrorContext::Limit {
                    resource: LimitKind::LinkRelocationCount,
                    ..
                }
            ) | (
                false,
                ErrorContext::Limit {
                    resource: LimitKind::LinkSymbolLookups,
                    ..
                }
            )
        ));
        assert_eq!(catalog.state.prepares.get(), prepared);
        assert_eq!(catalog.state.drops.get(), prepared);
    }
}

#[test]
fn link_resolves_an_undefined_weak_plt_slot_to_zero() {
    for profile in PROFILES {
        let (_, jump, _) = kinds(profile);
        let inputs = [fixture(
            profile,
            LoadPurpose::Executable,
            &[],
            &[(FUNC, STB_WEAK, STT_FUNC, STV_DEFAULT, SHN_UNDEF, 0)],
            &[],
            Some((PLT_SLOT, 1, jump, 0)),
        )];
        let mut catalog = Catalog::new(&inputs, &[]);
        let result = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
        assert_eq!(word(result.images()[0].allocation(), profile, PLT_SLOT), 0);
    }
}

#[test]
fn link_rejects_overlapping_target_mappings_before_copying_the_second_image() {
    let profile = LoadProfile::riscv64();
    let inputs = [
        fixture(profile, LoadPurpose::Executable, &[A], &[], &[], None),
        fixture(profile, LoadPurpose::SharedObject, &[], &[], &[], None),
    ];
    let mut catalog = Catalog::new(&inputs, ROUTES);
    let plan = discover(
        0,
        request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT),
        DependencyLimits::DEFAULT,
        &mut catalog,
    )
    .unwrap();
    let error = failure(link(
        plan,
        LinkLimits::DEFAULT,
        Allocator {
            state: catalog.state.clone(),
            base: 0x8000,
        },
    ));
    assert_eq!(error.kind(), LoadErrorKind::IncorrectLayout);
    assert_eq!(error.stage(), Some(LoadStage::Allocate));
    assert_eq!(catalog.state.writes.get(), 6);
    assert_eq!(catalog.state.live.get(), 0);
    assert_eq!(catalog.state.drops.get(), 2);
}

#[test]
fn link_releases_every_image_after_a_relocation_write_fails() {
    let profile = LoadProfile::riscv64();
    let relative = [(TARGET, 0, R_RISCV_RELATIVE, BASE as i64)];
    let inputs = [
        fixture(profile, LoadPurpose::Executable, &[A], &[], &relative, None),
        fixture(
            profile,
            LoadPurpose::SharedObject,
            &[],
            &[],
            &relative,
            None,
        ),
    ];
    let mut catalog = Catalog::new(&inputs, ROUTES);
    // Twelve segment-copy writes, one root relocation, then the failing DSO write.
    catalog.state.fail_write.set(Some(14));
    let error = failure(link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT));
    assert_eq!(error.stage(), Some(LoadStage::Relocate));
    assert_eq!(error.kind(), LoadErrorKind::Io);
    assert_eq!(catalog.state.writes.get(), 14);
    assert_eq!(catalog.state.live.get(), 0);
    assert_eq!(catalog.state.drops.get(), 2);
}
