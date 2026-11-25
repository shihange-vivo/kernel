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
        DT_PLTRELSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_RELA, DT_SONAME, DT_STRSZ, DT_STRTAB,
        DT_SYMENT, DT_SYMTAB,
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
    error::{ErrorContext, ExistingImageReason, LimitKind, LoadErrorKind, LoadStage},
    load_and_link,
    memory::{AllocationOffset, ImageLayout, MemoryPermissions, TargetAddress, TargetRange},
    profile::{
        DependencyLimits, ElfClass, ElfMachine, ExportLimits, LinkLimits, LoadLimits, LoadProfile,
        LoadPurpose,
    },
    CodeCache, ImageAllocator, ImageMapping, LoadAndLinkRequest, LoadError, LoadResult,
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
    } else {
        dynamic.push((DT_SONAME, A));
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
    link(plan, limits, DistinctAllocations(catalog.state().clone()))
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
        assert_eq!(catalog.state().live.get(), 5);
        drop(linked);
        assert_eq!(catalog.state().live.get(), 0);
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
    assert_eq!(catalog.state().live.get(), 2);
}

#[derive(Default)]
struct GraphCache {
    ranges: Vec<TargetRange>,
    fail_on: Option<usize>,
}

impl CodeCache for GraphCache {
    fn synchronize(&mut self, range: TargetRange) -> LoadResult<()> {
        self.ranges.push(range);
        if self.fail_on == Some(self.ranges.len()) {
            return Err(LoadError::new(LoadErrorKind::Backend, ErrorContext::None));
        }
        Ok(())
    }
}

#[test]
fn load_and_link_finalizes_every_image_and_retains_the_graph() {
    for profile in PROFILES {
        let relro_start = 0x2600;
        let mut fixtures = [
            lifecycle_fixture(profile, LoadPurpose::Executable, &[A], BASE + 0x10),
            lifecycle_fixture(profile, LoadPurpose::SharedObject, &[], BASE + 0x10),
        ];
        for fixture in &mut fixtures {
            super::seal::relro(fixture, relro_start, 0x80);
        }
        let mut catalog = Catalog::new(&fixtures, ROUTES);
        let state = catalog.state().clone();
        let mut cache = GraphCache::default();
        let loaded = load_and_link(
            0,
            LoadAndLinkRequest::new(request(
                profile,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
            )),
            &mut catalog,
            DistinctAllocations(state.clone()),
            &mut cache,
        )
        .unwrap();

        assert_eq!(loaded.images().len(), 2);
        assert!(loaded
            .images()
            .iter()
            .all(|object| object.exports().is_none()));
        assert_eq!(loaded.images()[1].key(), &1);
        assert_eq!(loaded.edges().len(), 1);
        assert_eq!(loaded.edges()[0].provider(), 1);
        assert_eq!(loaded.root().entry(), Some(TargetAddress::new(0x8000)));
        assert_eq!(loaded.images()[1].image().entry(), None);
        assert_eq!(loaded.preinit(), &[TargetAddress::new(0x8000)]);
        assert!(loaded
            .init()
            .map(TargetAddress::get)
            .eq([0xc010, 0xc020, 0x8010, 0x8020]));
        assert!(loaded
            .fini()
            .map(TargetAddress::get)
            .eq([0x8050, 0x8040, 0x8030, 0xc050, 0xc040, 0xc030]));
        assert_eq!(
            cache.ranges,
            [0x8000, 0xc000].map(|base| TargetRange::new(TargetAddress::new(base), 0x100))
        );
        let protection = state.protection.borrow();
        assert_eq!(
            &protection[protection.len() - 2..],
            &[(
                AllocationOffset::new(relro_start - BASE),
                0x80,
                MemoryPermissions::READ
            ); 2]
        );
        assert_eq!(state.reader_drops.get(), 2);
        assert_eq!(state.live.get(), 2);
        drop(protection);
        drop(loaded);
        assert_eq!(state.drops.get(), 2);
    }
}

#[test]
fn retained_exports_match_elf_lookup_after_the_reader_closes() {
    let profile = LoadProfile::riscv64();
    let mut root = fixture(
        profile,
        LoadPurpose::Executable,
        &[],
        &[
            (DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA),
            (DATA, STB_WEAK, STT_OBJECT, STV_PROTECTED, 1, LIB_DATA + 8),
            (FUNC, STB_GLOBAL, STT_FUNC, STV_HIDDEN, 1, BASE),
            (WEAK, STB_WEAK, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0),
        ],
        &[],
        None,
    );
    let hash = root.file_offset(HASH);
    // Search symbol 2 before symbol 1 although both names are the same.
    root.number(hash + 8, 2, 4);
    root.number(hash + 16, 3, 4);
    root.number(hash + 20, 1, 4);

    let fixtures = [root];
    let mut catalog = Catalog::new(&fixtures, &[]);
    let state = catalog.state().clone();
    let config = LoadAndLinkRequest::new(request(
        profile,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
    ))
    .with_link_limits(LinkLimits::DEFAULT.with_export_limits(ExportLimits::DEFAULT));
    let loaded = load_and_link(
        0,
        config,
        &mut catalog,
        DistinctAllocations(state.clone()),
        &mut GraphCache::default(),
    )
    .unwrap();

    assert_eq!(state.reader_drops.get(), 1);
    assert_eq!(state.live.get(), 1);
    let object = &loaded.images()[0];
    let exports = object.exports().unwrap();
    let address = object
        .image()
        .allocation()
        .base()
        .checked_add(LIB_DATA + 8 - BASE)
        .unwrap();
    assert_eq!(exports.find(b"data"), Some(address));
    assert_eq!(exports.find(b"func"), None);
    assert_eq!(exports.find(b"weak"), None);
    assert_eq!(exports.find(b"missing"), None);
}

#[test]
fn retained_exports_check_graph_limits_before_relocation_writes() {
    let profile = LoadProfile::riscv64();
    let symbols = [(DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA)];
    let fixtures = [
        fixture(
            profile,
            LoadPurpose::Executable,
            &[A],
            &symbols,
            &[(TARGET, 0, R_RISCV_RELATIVE, BASE as i64)],
            None,
        ),
        fixture(profile, LoadPurpose::SharedObject, &[], &symbols, &[], None),
    ];

    for (limits, name_bytes) in [
        (ExportLimits::new(0, 256), false),
        (ExportLimits::new(u64::MAX, 7), true),
    ] {
        let mut catalog = Catalog::new(&fixtures, ROUTES);
        let error = failure(link_fixtures(
            &mut catalog,
            profile,
            LinkLimits::DEFAULT.with_export_limits(limits),
        ));
        assert_eq!(error.stage(), Some(LoadStage::Relocate));
        assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
        assert!(matches!(
            (name_bytes, error.context()),
            (
                false,
                ErrorContext::Limit {
                    resource: LimitKind::LinkExportReads,
                    actual: 1,
                    maximum: 0,
                },
            ) | (
                true,
                ErrorContext::Limit {
                    resource: LimitKind::LinkExportNameBytes,
                    actual: 8,
                    maximum: 7,
                },
            )
        ));
        // Only the segment copies reached storage.
        assert_eq!(catalog.state().writes.get(), 12);
        assert_eq!(catalog.state().drops.get(), 2);
    }
}

#[test]
fn plugin_reuses_needed_images_and_searches_the_application_first() {
    for profile in PROFILES {
        let (address_kind, jump_kind, _) = kinds(profile);
        let fixtures = [
            fixture(
                profile,
                LoadPurpose::Executable,
                &[A],
                &[(FUNC, STB_GLOBAL, STT_FUNC, STV_DEFAULT, 1, BASE + 0x20)],
                &[],
                None,
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[B],
                &[(DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA)],
                &[],
                None,
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[],
                &[(WEAK, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA + 8)],
                &[],
                None,
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[A, B],
                &[
                    (FUNC, STB_GLOBAL, STT_FUNC, STV_DEFAULT, SHN_UNDEF, 0),
                    (DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0),
                    (WEAK, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0),
                ],
                &[
                    (TARGET, 2, address_kind, 0),
                    (TARGET + 8, 3, address_kind, 0),
                ],
                Some((PLT_SLOT, 1, jump_kind, 0)),
            ),
            fixture(
                profile,
                LoadPurpose::SharedObject,
                &[],
                &[(FUNC, STB_GLOBAL, STT_FUNC, STV_DEFAULT, 1, BASE + 0x40)],
                &[],
                None,
            ),
        ];
        let mut catalog = Catalog::new(
            &fixtures,
            &[(0, b"a", 1), (1, b"b", 2), (3, b"a", 1), (3, b"b", 4)],
        );
        let state = catalog.state().clone();
        let config = LoadAndLinkRequest::new(request(
            profile,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
        ))
        .with_link_limits(LinkLimits::DEFAULT.with_export_limits(ExportLimits::DEFAULT));
        let mut cache = GraphCache::default();
        let mut group = load_and_link(
            0,
            config,
            &mut catalog,
            DistinctAllocations(state.clone()),
            &mut cache,
        )
        .unwrap();
        let index = group
            .load_plugin(
                3,
                config,
                &mut catalog,
                DistinctAllocations(state.clone()),
                &mut cache,
            )
            .unwrap();
        assert_eq!(index, 3);
        assert_eq!(catalog.opened(), [0, 1, 2, 3, 4]);
        assert_eq!(state.prepares.get(), 5);
        assert_eq!(cache.ranges.len(), 5);
        assert_eq!(group.init_order(), [2, 1, 0, 4, 3]);
        assert_eq!(group.edges()[2].requester(), 3);
        assert_eq!(group.edges()[2].provider(), 1);
        assert_eq!(group.images()[1].soname(), Some(b"a".as_slice()));
        assert_eq!(group.images()[4].soname(), group.images()[1].soname());
        assert_ne!(group.images()[4].key(), group.images()[1].key());
        let plugin = group.images()[3].image().allocation();
        for (slot, provider, name) in [
            (PLT_SLOT, 0, b"func".as_slice()),
            (TARGET, 1, b"data"),
            (TARGET + 8, 2, b"weak"),
        ] {
            let address = group.images()[provider]
                .exports()
                .unwrap()
                .find(name)
                .unwrap();
            assert_eq!(word(plugin, profile, slot), address.get());
        }
        assert_eq!(
            group
                .load_plugin(
                    3,
                    config,
                    &mut catalog,
                    DistinctAllocations(state.clone()),
                    &mut cache
                )
                .unwrap(),
            3
        );
        assert_eq!(catalog.opened(), [0, 1, 2, 3, 4]);
        drop(group);
        assert_eq!(state.drops.get(), 5);
    }
}

#[test]
fn plugin_scope_only_includes_later_images_through_its_dependencies() {
    let profile = LoadProfile::riscv64();
    let fixtures = [
        fixture(profile, LoadPurpose::Executable, &[], &[], &[], None),
        fixture(
            profile,
            LoadPurpose::SharedObject,
            &[],
            &[(DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, 1, LIB_DATA)],
            &[],
            None,
        ),
        fixture(
            profile,
            LoadPurpose::SharedObject,
            &[],
            &[(DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0)],
            &[(TARGET, 1, R_RISCV_64, 0)],
            None,
        ),
        fixture(
            profile,
            LoadPurpose::SharedObject,
            &[A],
            &[(DATA, STB_GLOBAL, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0)],
            &[(TARGET, 1, R_RISCV_64, 0)],
            None,
        ),
    ];
    let mut catalog = Catalog::new(&fixtures, &[(3, b"a", 1)]);
    let state = catalog.state().clone();
    let config = LoadAndLinkRequest::new(request(
        profile,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
    ))
    .with_link_limits(LinkLimits::DEFAULT.with_export_limits(ExportLimits::DEFAULT));
    let mut cache = GraphCache::default();
    let mut group = load_and_link(
        0,
        config,
        &mut catalog,
        DistinctAllocations(state.clone()),
        &mut cache,
    )
    .unwrap();
    let mut load = |key| {
        group.load_plugin(
            key,
            config,
            &mut catalog,
            DistinctAllocations(state.clone()),
            &mut cache,
        )
    };
    assert_eq!(load(1).unwrap(), 1);
    let error = failure(load(2));
    assert_eq!(error.kind(), LoadErrorKind::UnresolvedSymbol);
    assert_eq!(state.live.get(), 2);
    assert_eq!(load(3).unwrap(), 2);
    assert_eq!(group.init_order(), [0, 1, 2]);
    assert_eq!(catalog.opened(), [0, 1, 2, 3]);
    let address = group.images()[1].exports().unwrap().find(b"data").unwrap();
    assert_eq!(group.lookup_symbol(2, b"data").unwrap(), Some(address));
    assert_eq!(group.lookup_symbol(0, b"data").unwrap(), None);
    assert_eq!(
        word(group.images()[2].image().allocation(), profile, TARGET),
        address.get()
    );
}

#[test]
fn plugin_errors_identify_the_existing_image_and_reason() {
    let profile = LoadProfile::riscv64();
    let fixtures = [
        fixture(profile, LoadPurpose::Executable, &[], &[], &[], None),
        fixture(profile, LoadPurpose::SharedObject, &[], &[], &[], None),
    ];
    let mut catalog = Catalog::new(&fixtures, &[]);
    let state = catalog.state().clone();
    let config = LoadAndLinkRequest::new(request(
        profile,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
    ));
    let mut cache = GraphCache::default();
    let mut group = load_and_link(
        0,
        config,
        &mut catalog,
        DistinctAllocations(state.clone()),
        &mut cache,
    )
    .unwrap();
    let root_base = group.root().allocation().base();

    let error = failure(group.lookup_symbol(0, b"data"));
    assert!(matches!(
        error.context(),
        ErrorContext::ExistingImage { index: 0, base, reason: ExistingImageReason::MissingExportIndex }
            if *base == root_base
    ));
    let error = failure(group.lookup_symbol(1, b"data"));
    assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
    assert!(matches!(
        error.context(),
        ErrorContext::ImageIndex { index: 1, count: 1 }
    ));

    for (key, reason) in [
        (0, ExistingImageReason::RootAsPlugin),
        (1, ExistingImageReason::MissingExportIndex),
    ] {
        let error = failure(group.load_plugin(
            key,
            config,
            &mut catalog,
            DistinctAllocations(state.clone()),
            &mut cache,
        ));
        assert_eq!(error.stage(), Some(LoadStage::Discover));
        assert!(matches!(
            error.context(),
            ErrorContext::ExistingImage { index: 0, base, reason: actual }
                if *base == root_base && *actual == reason
        ));
    }
    assert_eq!(state.prepares.get(), 1);
}

#[test]
fn graph_seal_checks_all_callbacks_before_synchronizing_code() {
    let profile = LoadProfile::riscv64();
    let fixtures = [
        lifecycle_fixture(profile, LoadPurpose::Executable, &[A], BASE + 0x10),
        lifecycle_fixture(profile, LoadPurpose::SharedObject, &[], LIB_DATA),
    ];
    let mut catalog = Catalog::new(&fixtures, ROUTES);
    let linked = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
    let mut cache = GraphCache::default();
    let error = failure(linked.seal(&mut cache));
    assert_eq!(error.stage(), Some(LoadStage::Lifecycle));
    assert!(cache.ranges.is_empty());
    assert_eq!(catalog.state().drops.get(), 2);
}

#[test]
fn graph_seal_releases_all_mappings_after_a_late_cache_error() {
    let profile = LoadProfile::riscv64();
    let fixtures = [
        lifecycle_fixture(profile, LoadPurpose::Executable, &[A], BASE + 0x10),
        lifecycle_fixture(profile, LoadPurpose::SharedObject, &[], BASE + 0x10),
    ];
    let mut catalog = Catalog::new(&fixtures, ROUTES);
    let linked = link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT).unwrap();
    let mut cache = GraphCache {
        fail_on: Some(2),
        ..GraphCache::default()
    };
    let error = failure(linked.seal(&mut cache));
    assert_eq!(error.stage(), Some(LoadStage::Seal));
    assert_eq!(error.kind(), LoadErrorKind::Backend);
    assert_eq!(cache.ranges.len(), 2);
    assert!(matches!(
        error.context(),
        ErrorContext::TargetRange { start, len: 0x100, .. } if start.get() == 0xc000
    ));
    assert_eq!(catalog.state().drops.get(), 2);
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
        assert_eq!(catalog.state().reader_drops.get(), 3);
        assert_eq!(catalog.state().live.get(), 3);
        drop(result);
        assert_eq!(catalog.state().drops.get(), 3);
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
        assert_eq!(catalog.state().live.get(), 0);
        assert_eq!(catalog.state().drops.get(), 2);
        // Two file-backed segments per fixture, copied in 512-byte chunks.
        assert_eq!(catalog.state().writes.get(), 12);
    }
}

#[test]
fn load_and_link_checks_dependency_relocation_and_probe_budgets() {
    let profile = LoadProfile::aarch64();
    let inputs = [fixture(
        profile,
        LoadPurpose::Executable,
        &[],
        &[(DATA, STB_WEAK, STT_OBJECT, STV_DEFAULT, SHN_UNDEF, 0)],
        &[(TARGET, 1, R_AARCH64_ABS64, 0)],
        None,
    )];
    let config = LoadAndLinkRequest::new(request(
        profile,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
    ));
    for (config, stage, prepared) in [
        (
            config.with_dependency_limits(DependencyLimits::new(0, 0, 0, 0, 0)),
            LoadStage::Discover,
            0,
        ),
        (
            config.with_link_limits(LinkLimits::new(0, 1, 256)),
            LoadStage::Relocate,
            0,
        ),
        (
            config.with_link_limits(LinkLimits::new(1, 0, 256)),
            LoadStage::Relocate,
            1,
        ),
    ] {
        let mut catalog = Catalog::new(&inputs, &[]);
        let allocator = DistinctAllocations(catalog.state().clone());
        let error = failure(load_and_link(
            0,
            config,
            &mut catalog,
            allocator,
            &mut GraphCache::default(),
        ));
        assert_eq!(error.stage(), Some(stage));
        assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
        assert!(matches!(
            (stage, prepared, error.context()),
            (
                LoadStage::Discover,
                0,
                ErrorContext::Limit {
                    resource: LimitKind::DependencyImageCount,
                    ..
                }
            ) | (
                LoadStage::Relocate,
                0,
                ErrorContext::Limit {
                    resource: LimitKind::LinkRelocationCount,
                    ..
                }
            ) | (
                LoadStage::Relocate,
                1,
                ErrorContext::Limit {
                    resource: LimitKind::LinkSymbolLookups,
                    ..
                }
            )
        ));
        assert_eq!(catalog.state().prepares.get(), prepared);
        assert_eq!(catalog.state().drops.get(), prepared);
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
            state: catalog.state().clone(),
            base: 0x8000,
        },
    ));
    assert_eq!(error.kind(), LoadErrorKind::IncorrectLayout);
    assert_eq!(error.stage(), Some(LoadStage::Allocate));
    assert_eq!(catalog.state().writes.get(), 6);
    assert_eq!(catalog.state().live.get(), 0);
    assert_eq!(catalog.state().drops.get(), 2);
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
    catalog.state().fail_write.set(Some(14));
    let error = failure(link_fixtures(&mut catalog, profile, LinkLimits::DEFAULT));
    assert_eq!(error.stage(), Some(LoadStage::Relocate));
    assert_eq!(error.kind(), LoadErrorKind::Io);
    assert_eq!(catalog.state().writes.get(), 14);
    assert_eq!(catalog.state().live.get(), 0);
    assert_eq!(catalog.state().drops.get(), 2);
}
