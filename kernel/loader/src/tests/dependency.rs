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

//! Dependency discovery through the public resolver and plan interfaces.

use alloc::{rc::Rc, vec::Vec};

use blueos_test_macro::test;
use goblin::elf::dynamic::{
    DF_1_PIE, DT_FLAGS_1, DT_NEEDED, DT_NULL, DT_SONAME, DT_STRSZ, DT_STRTAB,
};

use super::{failure, request, Fixture, Input, State, PROFILES, STRVA};
use crate::{
    dynamic_linker::{discover, DependencyResolver},
    error::{ErrorContext, LimitKind, LoadErrorKind, LoadStage},
    profile::{DependencyLimits, LoadLimits, LoadProfile, LoadPurpose},
    LoadError, LoadResult,
};

const STRINGS: &[u8] = b"\0a\0b\0lib\xff.so\0alias\0";
const A: u64 = 1;
const B: u64 = 3;
const C: u64 = 5;
const ALIAS: u64 = 13;

fn fixture(
    profile: LoadProfile,
    needed: &[u64],
    soname: Option<u64>,
    strings: &[u8],
    purpose: LoadPurpose,
) -> Fixture {
    let mut tags = Vec::from([(DT_STRTAB, STRVA), (DT_STRSZ, strings.len() as u64)]);
    tags.extend(needed.iter().map(|&offset| (DT_NEEDED, offset)));
    tags.extend(soname.map(|offset| (DT_SONAME, offset)));
    if purpose == LoadPurpose::Executable {
        tags.push((DT_FLAGS_1, DF_1_PIE));
    }
    tags.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &tags);
    let offset = fixture.file_offset(STRVA);
    fixture.bytes[offset..offset + strings.len()].copy_from_slice(strings);
    if purpose == LoadPurpose::SharedObject {
        fixture.entry(0);
    }
    fixture
}

type Route<'a> = (usize, &'a [u8], usize);

struct Catalog<'a> {
    fixtures: &'a [Fixture],
    routes: &'a [Route<'a>],
    state: Rc<State>,
    opens: Vec<usize>,
    resolves: usize,
}

impl<'a> Catalog<'a> {
    fn new(fixtures: &'a [Fixture], routes: &'a [Route<'a>]) -> Self {
        Self {
            fixtures,
            routes,
            state: Rc::new(State::default()),
            opens: Vec::new(),
            resolves: 0,
        }
    }
}

impl<'a> DependencyResolver for Catalog<'a> {
    type Key = usize;
    type Reader = Input<'a>;

    fn resolve(&mut self, requester: &usize, needed: &[u8]) -> LoadResult<usize> {
        self.resolves += 1;
        self.routes
            .iter()
            .find(|(from, name, _)| from == requester && *name == needed)
            .map(|&(_, _, key)| key)
            .ok_or_else(missing)
    }

    fn open(&mut self, key: &usize) -> LoadResult<Self::Reader> {
        self.opens.push(*key);
        let fixture = self.fixtures.get(*key).ok_or_else(missing)?;
        Ok(Input {
            fixture,
            state: self.state.clone(),
        })
    }
}

fn missing() -> LoadError {
    LoadError::new(LoadErrorKind::Io, ErrorContext::None)
}

#[test]
fn discovery_preserves_dependency_order_and_deduplicates_a_diamond_and_cycle() {
    for profile in PROFILES {
        let fixtures = [
            fixture(profile, &[A, B], None, STRINGS, LoadPurpose::Executable),
            fixture(profile, &[C], Some(A), STRINGS, LoadPurpose::SharedObject),
            fixture(
                profile,
                &[ALIAS, ALIAS],
                Some(A),
                STRINGS,
                LoadPurpose::SharedObject,
            ),
            fixture(profile, &[A], Some(C), STRINGS, LoadPurpose::SharedObject),
        ];
        let routes: &[Route<'_>] = &[
            (0, b"a", 1),
            (0, b"b", 2),
            (1, b"lib\xff.so", 3),
            (2, b"alias", 3),
            (3, b"a", 1),
        ];
        let mut catalog = Catalog::new(&fixtures, routes);
        let plan = discover(
            0,
            request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT),
            DependencyLimits::new(4, 6, 2, 7, 4 * fixtures[0].file_len),
            &mut catalog,
        )
        .unwrap();
        assert_eq!(catalog.opens, [0, 1, 2, 3]);
        assert_eq!(catalog.resolves, 6);
        let images = plan
            .images()
            .iter()
            .map(|image| (*image.key(), image.depth(), image.soname()))
            .collect::<Vec<_>>();
        assert_eq!(
            images,
            [
                (0, 0, None),
                (1, 1, Some(b"a".as_slice())),
                (2, 1, Some(b"a".as_slice())),
                (3, 2, Some(b"lib\xff.so".as_slice())),
            ]
        );
        let edges = plan
            .edges()
            .iter()
            .map(|edge| (edge.requester(), edge.provider(), edge.name()))
            .collect::<Vec<_>>();
        assert_eq!(
            edges,
            [
                (0, 1, b"a".as_slice()),
                (0, 2, b"b"),
                (1, 3, b"lib\xff.so"),
                (2, 3, b"alias"),
                (2, 3, b"alias"),
                (3, 1, b"a"),
            ]
        );
        assert_eq!(catalog.state.prepares.get(), 0);
        assert_eq!(catalog.state.reader_drops.get(), 0);
        drop(plan);
        assert_eq!(catalog.state.reader_drops.get(), 4);
    }
}

#[test]
fn discovery_counts_unique_depth_and_keeps_the_root_at_depth_zero() {
    let profile = LoadProfile::riscv32();
    let input = [fixture(
        profile,
        &[A],
        Some(A),
        STRINGS,
        LoadPurpose::SharedObject,
    )];
    let mut catalog = Catalog::new(&input, &[(0, b"a", 0)]);
    // A shared-object root can satisfy a reference to itself at depth zero.
    let plan = discover(
        0,
        request(profile, LoadPurpose::SharedObject, LoadLimits::DEFAULT),
        DependencyLimits::new(1, 1, 0, 1, input[0].file_len),
        &mut catalog,
    )
    .unwrap();
    assert_eq!(catalog.opens, [0]);
    assert_eq!(plan.images()[0].depth(), 0);
    assert_eq!(plan.edges()[0].provider(), 0);
    drop(plan);

    let input = [fixture(
        profile,
        &[A],
        None,
        STRINGS,
        LoadPurpose::Executable,
    )];
    let mut catalog = Catalog::new(&input, &[(0, b"a", 0)]);
    let error = failure(discover(
        0,
        request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT),
        DependencyLimits::DEFAULT,
        &mut catalog,
    ));
    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
    assert_eq!(error.stage(), Some(LoadStage::Discover));
    assert!(matches!(
        error.context(),
        ErrorContext::Dependency {
            requester: 0,
            needed_index: 0
        }
    ));
    assert_eq!(catalog.state.reader_drops.get(), 1);
}

#[test]
fn discovery_checks_limits_before_opening_unneeded_inputs() {
    let profile = LoadProfile::riscv64();
    let input = [
        fixture(profile, &[A], None, STRINGS, LoadPurpose::Executable),
        fixture(profile, &[], None, STRINGS, LoadPurpose::SharedObject),
    ];
    let file_len = input[0].file_len;
    for (limits, resource, opened, resolved) in [
        (
            DependencyLimits::new(0, 1, 1, 1, file_len * 2),
            LimitKind::DependencyImageCount,
            0,
            0,
        ),
        (
            DependencyLimits::new(1, 1, 1, 1, file_len * 2),
            LimitKind::DependencyImageCount,
            1,
            1,
        ),
        (
            DependencyLimits::new(2, 1, 0, 1, file_len * 2),
            LimitKind::DependencyDepth,
            1,
            1,
        ),
        (
            DependencyLimits::new(2, 0, 1, 1, file_len * 2),
            LimitKind::DependencyEdgeCount,
            1,
            0,
        ),
        (
            DependencyLimits::new(2, 1, 1, 1, file_len),
            LimitKind::DependencyInputBytes,
            2,
            1,
        ),
    ] {
        let mut catalog = Catalog::new(&input, &[(0, b"a", 1)]);
        let error = failure(discover(
            0,
            request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT),
            limits,
            &mut catalog,
        ));
        assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
        assert_eq!(error.stage(), Some(LoadStage::Discover));
        assert!(
            matches!(error.context(), ErrorContext::Limit { resource: actual, .. }
            if core::mem::discriminant(actual) == core::mem::discriminant(&resource))
        );
        assert_eq!(catalog.opens.len(), opened);
        assert_eq!(catalog.resolves, resolved);
        assert_eq!(catalog.state.reader_drops.get(), opened);
    }
}

#[test]
fn discovery_bounds_names_to_dynstr_and_preserves_bytes_across_reads() {
    let profile = LoadProfile::aarch64();
    let request = request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT);
    for (needed, soname, strings, stage) in [
        (Some(3), None, b"\0a\0".as_slice(), LoadStage::Plan),
        (Some(0), None, b"\0a\0", LoadStage::Discover),
        (Some(1), None, b"\0a", LoadStage::Discover),
        (None, Some(1), b"\0a", LoadStage::Discover),
    ] {
        let needed = needed.as_slice();
        let input = [fixture(
            profile,
            needed,
            soname,
            strings,
            LoadPurpose::Executable,
        )];
        let mut catalog = Catalog::new(&input, &[]);
        let error = failure(discover(
            0,
            request,
            DependencyLimits::DEFAULT,
            &mut catalog,
        ));
        assert_eq!(error.kind(), LoadErrorKind::BadElf);
        assert_eq!(error.stage(), Some(stage));
        assert_eq!(catalog.resolves, 0);
        assert_eq!(catalog.state.reader_drops.get(), 1);
    }

    let mut strings = [b'x'; 72];
    strings[0] = 0;
    strings[65] = 0xff;
    strings[71] = 0;
    let input = [
        fixture(profile, &[1], None, &strings, LoadPurpose::Executable),
        fixture(profile, &[], Some(1), &strings, LoadPurpose::SharedObject),
    ];
    let routes = [(0, &strings[1..71], 1)];
    let mut catalog = Catalog::new(&input, &routes);
    let plan = discover(
        0,
        request,
        DependencyLimits::new(2, 1, 1, 70, 2 * input[0].file_len),
        &mut catalog,
    )
    .unwrap();
    assert_eq!(plan.edges()[0].name(), &strings[1..71]);
    assert_eq!(plan.images()[1].soname(), Some(&strings[1..71]));

    let mut catalog = Catalog::new(&input, &routes);
    let error = failure(discover(
        0,
        request,
        DependencyLimits::new(2, 1, 1, 69, 2 * input[0].file_len),
        &mut catalog,
    ));
    assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
    assert_eq!(error.stage(), Some(LoadStage::Discover));
    assert_eq!(catalog.resolves, 0);
    assert_eq!(catalog.state.reader_drops.get(), 1);
}

#[test]
fn discovery_drops_open_readers_after_host_or_admission_failure() {
    let profile = LoadProfile::riscv64();
    let input = [
        fixture(profile, &[A], None, STRINGS, LoadPurpose::Executable),
        fixture(profile, &[B], None, STRINGS, LoadPurpose::SharedObject),
        fixture(profile, &[], None, STRINGS, LoadPurpose::Executable),
    ];
    let request = request(profile, LoadPurpose::Executable, LoadLimits::DEFAULT);
    let missing_route: &[Route<'_>] = &[(0, b"a", 1)];
    let missing_file: &[Route<'_>] = &[(0, b"a", 1), (1, b"b", 3)];
    let pie_provider: &[Route<'_>] = &[(0, b"a", 1), (1, b"b", 2)];
    for (routes, kind, stage, opened, dropped) in [
        (missing_route, LoadErrorKind::Io, LoadStage::Discover, 2, 2),
        (missing_file, LoadErrorKind::Io, LoadStage::Discover, 3, 2),
        (
            pie_provider,
            LoadErrorKind::UnsupportedByProfile,
            LoadStage::Plan,
            3,
            3,
        ),
    ] {
        let mut catalog = Catalog::new(&input, routes);
        let error = failure(discover(
            0,
            request,
            DependencyLimits::DEFAULT,
            &mut catalog,
        ));
        assert_eq!(error.kind(), kind);
        assert_eq!(error.stage(), Some(stage));
        if stage == LoadStage::Discover {
            assert!(matches!(
                error.context(),
                ErrorContext::Dependency {
                    requester: 1,
                    needed_index: 0
                }
            ));
        }
        assert_eq!(catalog.opens.len(), opened);
        assert_eq!(catalog.state.reader_drops.get(), dropped);
        assert_eq!(catalog.state.prepares.get(), 0);
    }
}
