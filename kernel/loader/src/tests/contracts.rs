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

//! Exercise the public pipeline using target addresses that are never host
//! pointers.
use super::fixture::{ElfFixtureBuilder, ProgramHeaderFixture, SliceElfReader};
use crate::{
    memory::*,
    profile::{ElfClass, ElfMachine, LoadProfile, SessionLimits},
    ArtifactId, ArtifactInfo, ArtifactResolver, ExecutionDomainId, ImageKey, LoadRequest,
    LoadResult, LoadServices, LocalRepository, OpenedArtifact, RetainResources,
};
use alloc::{rc::Rc, vec::Vec};
use blueos_test_macro::test;
use core::cell::RefCell;
fn failure() -> crate::LoadError {
    crate::error::invalid()
}
#[derive(Default)]
struct MemoryState {
    allocation: Option<ImageAllocation>,
    segments: Vec<SegmentBacking>,
    layouts: Vec<ImageLayout>,
    fail_segment: Option<usize>,
    aborts: usize,
    releases: usize,
    protects: usize,
    reject_protect: bool,
}
struct SegmentBacking {
    layout: SegmentLayout,
    bytes: Vec<u8>,
}

impl MemoryState {
    fn backing(&self, offset: AllocationOffset, len: usize) -> LoadResult<(usize, usize)> {
        let start = offset.value();
        let end = start.checked_add(len as u64).ok_or_else(failure)?;
        self.segments
            .iter()
            .enumerate()
            .find_map(|(index, segment)| {
                let lo = segment.layout.offset().value();
                let hi = lo + segment.layout.memory_size();
                (start >= lo && end <= hi).then(|| (index, (start - lo) as usize))
            })
            .ok_or_else(failure)
    }
}

#[derive(Clone, Default)]
#[must_use = "the target memory service retains allocation backing"]
struct TargetMemory(Rc<RefCell<MemoryState>>);
impl ImageMemory for TargetMemory {
    fn execution_domain(&self) -> ExecutionDomainId {
        ExecutionDomainId::new(99)
    }
    fn prepare_image(&mut self, layout: &ImageLayout) -> LoadResult<AllocationLease> {
        let r = layout.request();
        let mut s = self.0.borrow_mut();
        assert!(s.allocation.is_none());
        let a = ImageAllocation::with_identity(
            AllocationId::new(1),
            match r.placement() {
                Placement::Anywhere => TargetAddress::new(0x100000),
                Placement::Fixed(range) => range.start(),
            },
            r.size(),
            r.align(),
            AllocationOwnership::Owned,
        );
        // Stage all backing locally: a failed later segment publishes nothing.
        let mut segments = Vec::new();
        for (index, segment) in layout.segments().iter().enumerate() {
            if s.fail_segment == Some(index) {
                return Err(failure());
            }
            segments.push(SegmentBacking {
                layout: *segment,
                bytes: alloc::vec![0xa5; segment.memory_size() as usize],
            });
        }
        s.layouts.push(layout.clone());
        s.segments = segments;
        s.allocation = Some(a);
        // SAFETY: this state records one allocation and mints its only lease.
        Ok(unsafe { AllocationLease::new(a) })
    }
    fn abort_image(&mut self, _: AllocationLease, _: MutationProgress) {
        let mut s = self.0.borrow_mut();
        s.allocation = None;
        s.segments.clear();
        s.aborts += 1;
    }
    fn release_committed(&mut self, _: AllocationLease) {
        let mut s = self.0.borrow_mut();
        s.allocation = None;
        s.segments.clear();
        s.releases += 1;
    }
    fn validate_range(&self, a: &ImageAllocation, o: AllocationOffset, n: u64) -> LoadResult<()> {
        let s = self.0.borrow();
        if s.allocation != Some(*a) || o.value().checked_add(n).is_none_or(|e| e > a.len()) {
            return Err(failure());
        }
        Ok(())
    }
    fn read(&self, a: &ImageAllocation, o: AllocationOffset, dst: &mut [u8]) -> LoadResult<()> {
        self.validate_range(a, o, dst.len() as u64)?;
        if !dst.is_empty() {
            let state = self.0.borrow();
            let (index, at) = state.backing(o, dst.len())?;
            dst.copy_from_slice(&state.segments[index].bytes[at..at + dst.len()]);
        }
        Ok(())
    }
    fn write(&mut self, a: &ImageAllocation, o: AllocationOffset, src: &[u8]) -> LoadResult<()> {
        self.validate_range(a, o, src.len() as u64)?;
        if !src.is_empty() {
            let mut state = self.0.borrow_mut();
            let (index, at) = state.backing(o, src.len())?;
            state.segments[index].bytes[at..at + src.len()].copy_from_slice(src);
        }
        Ok(())
    }
    fn zero(&mut self, a: &ImageAllocation, o: AllocationOffset, n: u64) -> LoadResult<()> {
        self.validate_range(a, o, n)?;
        if n != 0 {
            let mut state = self.0.borrow_mut();
            let (index, at) = state.backing(o, n as usize)?;
            state.segments[index].bytes[at..at + n as usize].fill(0);
        }
        Ok(())
    }
}
impl ImageProtectionMemory for TargetMemory {
    fn protection_capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities::new(1, usize::MAX)
    }
    fn validate_protection_aliases(
        &self,
        a: &ImageAllocation,
        _: &PreparedProtectionPlan,
    ) -> LoadResult<()> {
        self.validate_range(a, AllocationOffset::new(0), a.len())
    }
    fn protect(
        &mut self,
        a: &ImageAllocation,
        o: AllocationOffset,
        n: u64,
        _: MemoryPermissions,
    ) -> LoadResult<ProtectionLevel> {
        self.validate_range(a, o, n)?;
        let mut s = self.0.borrow_mut();
        s.protects += 1;
        if s.reject_protect {
            Err(failure())
        } else {
            Ok(ProtectionLevel::LogicalOnly)
        }
    }
}
struct Source {
    bytes: Vec<u8>,
}
impl ArtifactResolver for Source {
    type Source = ArtifactInfo;
    type Reader = OwnedReader;
    fn info<'a>(&self, s: &'a ArtifactInfo) -> &'a ArtifactInfo {
        s
    }
    fn resolve(&mut self, _: &ArtifactInfo, _: &[u8]) -> LoadResult<ArtifactInfo> {
        Err(failure())
    }
    fn open(&mut self, _: &ArtifactInfo) -> LoadResult<OpenedArtifact<OwnedReader>> {
        Ok(OpenedArtifact::new(
            OwnedReader(self.bytes.clone()),
            ArtifactId::fresh()?,
        ))
    }
}
struct OwnedReader(Vec<u8>);
impl crate::reader::ElfReader for OwnedReader {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> LoadResult<()> {
        crate::reader::ElfReader::read_exact_at(&SliceElfReader::new(&self.0), o, b)
    }
}
#[derive(Default)]
struct Cache {
    fail: u8,
    domain: Option<ExecutionDomainId>,
    ranges: Vec<TargetRange>,
    syncs: usize,
    all_contexts: bool,
}
impl CodeCache for Cache {
    type Prepared = PreparedCacheSync;
    fn required_scope(&self) -> ExecutionScope {
        if self.all_contexts {
            ExecutionScope::AllExecutionContexts
        } else {
            ExecutionScope::CurrentExecutionContext
        }
    }
    fn execution_domain(&self) -> ExecutionDomainId {
        self.domain.unwrap_or(ExecutionDomainId::new(99))
    }
    fn prepare(
        &mut self,
        r: &[TargetRange],
        scope: ExecutionScope,
    ) -> LoadResult<PreparedCacheSync> {
        if self.fail == 1 {
            return Err(failure());
        }
        self.ranges = r.to_vec();
        PreparedCacheSync::try_new(
            if self.fail == 2 { &[] } else { r },
            if self.fail == 5 {
                ExecutionScope::CurrentExecutionContext
            } else {
                scope
            },
            CacheMaintenance::CoherentInstructionCache,
        )
    }
    fn synchronize(&mut self, _: PreparedCacheSync) -> LoadResult<()> {
        self.syncs += 1;
        if self.fail == 3 {
            Err(failure())
        } else {
            Ok(())
        }
    }
}
fn source() -> ArtifactInfo {
    ArtifactInfo::new(ImageKey::new(99, b"input").unwrap(), false)
}
fn profiles() -> [LoadProfile; 4] {
    [
        LoadProfile::arm_thumb_soft_float(),
        LoadProfile::riscv32(),
        LoadProfile::riscv64(),
        LoadProfile::aarch64(),
    ]
}
fn builder(p: LoadProfile) -> ElfFixtureBuilder {
    let machine = match p.machine() {
        ElfMachine::Arm => 40,
        ElfMachine::Riscv => 243,
        ElfMachine::Aarch64 => 183,
        ElfMachine::Other(_) => unreachable!(),
    };
    let b = if p.class() == ElfClass::Elf32 {
        ElfFixtureBuilder::elf32(machine, 3)
    } else {
        ElfFixtureBuilder::elf64(machine, 3)
    };
    b.with_flags(if p.machine() == ElfMachine::Arm {
        0x05000200
    } else {
        0
    })
}
fn executable(p: LoadProfile) -> Vec<u8> {
    builder(p)
        .with_load_segment(0x1000, 0x100, 0x100, 4)
        .with_entry(0x1000 | u64::from(p.entry_mode().is_thumb()))
        .build()
}

#[test]
fn target_memory_loads_every_profile_without_host_addresses() {
    for profile in profiles() {
        let memory = TargetMemory::default();
        let mut cache = Cache::default();
        let mut files = Source {
            bytes: executable(profile),
        };
        let loaded = crate::load(
            LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
            LoadServices {
                sources: &mut files,
                images: &mut LocalRepository,
                memory: memory.clone(),
                cache: &mut cache,
                observer: &mut (),
            },
            &mut RetainResources,
        )
        .unwrap();
        assert_eq!(
            loaded.entry().unwrap().get(),
            0x100000 | u64::from(profile.entry_mode().is_thumb()),
        );
        assert_eq!(cache.ranges.len(), 1);
        assert_eq!(cache.ranges[0].start().get(), 0x100000);
        assert_eq!(cache.syncs, 1);
        assert!(memory.0.borrow().protects > 0);
        drop(loaded);
        assert_eq!(memory.0.borrow().releases, 1);
    }
}

#[test]
fn cache_and_protection_failures_abort_before_publication() {
    for failure_point in 1..=4 {
        let profile = LoadProfile::riscv64();
        let memory = TargetMemory::default();
        memory.0.borrow_mut().reject_protect = failure_point == 4;
        let mut cache = Cache {
            fail: failure_point,
            ..Cache::default()
        };
        let mut files = Source {
            bytes: executable(profile),
        };
        assert!(crate::load(
            LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
            LoadServices {
                sources: &mut files,
                images: &mut LocalRepository,
                memory: memory.clone(),
                cache: &mut cache,
                observer: &mut (),
            },
            &mut RetainResources,
        )
        .is_err());
        let s = memory.0.borrow();
        assert_eq!(s.aborts, 1);
        assert_eq!(s.releases, 0);
        assert!(s.allocation.is_none());
        if failure_point < 4 {
            assert_eq!(s.protects, 0);
        }
    }
}

struct NeverOpened;
impl ArtifactResolver for NeverOpened {
    type Source = ArtifactInfo;
    type Reader = OwnedReader;
    fn info<'a>(&self, source: &'a ArtifactInfo) -> &'a ArtifactInfo {
        source
    }
    fn resolve(&mut self, _: &ArtifactInfo, _: &[u8]) -> LoadResult<ArtifactInfo> {
        panic!("domain mismatch must reject before resolution")
    }
    fn open(&mut self, _: &ArtifactInfo) -> LoadResult<OpenedArtifact<OwnedReader>> {
        panic!("domain mismatch must reject before opening input")
    }
}

#[test]
fn mismatched_execution_domain_rejects_before_open_or_allocation() {
    let profile = LoadProfile::riscv64();
    let memory = TargetMemory::default();
    let mut files = NeverOpened;
    let mut cache = Cache {
        domain: Some(ExecutionDomainId::FLAT),
        ..Cache::default()
    };
    assert!(crate::prepare_load(
        LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
        LoadServices {
            sources: &mut files,
            images: &mut LocalRepository,
            memory: memory.clone(),
            cache: &mut cache,
            observer: &mut (),
        },
    )
    .is_err());
    assert_eq!(memory.0.borrow().aborts, 0);
}

#[test]
fn relative_relocations_follow_the_requested_profile_on_the_same_host() {
    use goblin::elf::dynamic::*;
    for p in profiles() {
        let arm = p.machine() == ElfMachine::Arm;
        let word = if p.class() == ElfClass::Elf32 { 4 } else { 8 };
        let dynoff = if word == 4 { 116 } else { 176 };
        let relent = if arm {
            8
        } else if word == 4 {
            12
        } else {
            24
        };
        let mut bytes = builder(p)
            .with_program_header(ProgramHeaderFixture {
                kind: 1,
                flags: 6,
                offset: 0,
                vaddr: TargetAddress::new(0x1000),
                filesz: 0x400,
                memsz: 0x400,
                align: 4,
            })
            .with_dynamic_entries(
                0x1000 + dynoff,
                &[
                    (if arm { DT_REL } else { DT_RELA } as u32, 0x1280),
                    (if arm { DT_RELSZ } else { DT_RELASZ } as u32, relent),
                    (if arm { DT_RELENT } else { DT_RELAENT } as u32, relent),
                ],
            )
            .build();
        bytes.resize(0x400, 0);
        let kind = if arm {
            23u64
        } else if p.machine() == ElfMachine::Aarch64 {
            1027
        } else {
            3
        };
        if word == 4 {
            bytes[0x280..0x284].copy_from_slice(&0x1300u32.to_le_bytes());
            bytes[0x284..0x288].copy_from_slice(&(kind as u32).to_le_bytes());
            if arm {
                bytes[0x300..0x304].copy_from_slice(&0x1020u32.to_le_bytes());
            } else {
                bytes[0x288..0x28c].copy_from_slice(&0x1020u32.to_le_bytes());
            }
        } else {
            bytes[0x280..0x288].copy_from_slice(&0x1300u64.to_le_bytes());
            bytes[0x288..0x290].copy_from_slice(&kind.to_le_bytes());
            bytes[0x290..0x298].copy_from_slice(&0x1020u64.to_le_bytes());
        }
        let memory = TargetMemory::default();
        let mut files = Source { bytes };
        let mut cache = Cache::default();
        let loaded = crate::load(
            LoadRequest::shared_object(source(), p, SessionLimits::DEFAULT),
            LoadServices {
                sources: &mut files,
                images: &mut LocalRepository,
                memory: memory.clone(),
                cache: &mut cache,
                observer: &mut (),
            },
            &mut RetainResources,
        )
        .unwrap();
        let mut result = [0u8; 8];
        let allocation = memory.0.borrow().allocation.unwrap();
        memory
            .read(
                &allocation,
                AllocationOffset::new(0x300),
                &mut result[..word],
            )
            .unwrap();
        assert_eq!(u64::from_le_bytes(result), 0x100020);
        drop(loaded);
    }
}

#[test]
fn immutable_input_budget_is_checked_before_mapping() {
    let memory = TargetMemory::default();
    let mut files = Source {
        bytes: executable(LoadProfile::riscv64()),
    };
    let error = crate::prepare_load(
        LoadRequest::executable(
            source(),
            LoadProfile::riscv64(),
            SessionLimits::DEFAULT.with_total_input_bytes(0),
        ),
        LoadServices {
            sources: &mut files,
            images: &mut LocalRepository,
            memory: memory.clone(),
            cache: &mut Cache::default(),
            observer: &mut (),
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), crate::error::LoadErrorKind::ResourceLimit);
    assert_eq!(memory.0.borrow().aborts, 0);
    assert!(memory.0.borrow().allocation.is_none());
}

#[test]
fn insufficient_cache_scope_rejects_before_instruction_publication() {
    let profile = LoadProfile::riscv64();
    let memory = TargetMemory::default();
    let mut files = Source {
        bytes: executable(profile),
    };
    let mut cache = Cache {
        all_contexts: true,
        fail: 5,
        ..Cache::default()
    };
    assert!(crate::prepare_load(
        LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
        LoadServices {
            sources: &mut files,
            images: &mut LocalRepository,
            memory: memory.clone(),
            cache: &mut cache,
            observer: &mut (),
        },
    )
    .is_err());
    assert_eq!(cache.syncs, 0);
    assert_eq!(memory.0.borrow().aborts, 1);
    assert_eq!(memory.0.borrow().protects, 0);
}

#[test]
fn lifecycle_plans_keep_exact_owners_and_never_execute_callbacks() {
    use goblin::elf::dynamic::{DT_FINI, DT_INIT};
    for profile in profiles() {
        let thumb = u64::from(profile.entry_mode().is_thumb());
        let dynoff = if profile.class() == ElfClass::Elf32 {
            116
        } else {
            176
        };
        let mut bytes = builder(profile)
            .with_program_header(ProgramHeaderFixture {
                kind: 1,
                flags: 5,
                offset: 0,
                vaddr: TargetAddress::new(0x1000),
                filesz: 0x400,
                memsz: 0x400,
                align: 4,
            })
            .with_entry(0x1000 | thumb)
            .with_dynamic_entries(
                0x1000 + dynoff,
                &[
                    (DT_INIT as u32, 0x1320 | thumb),
                    (DT_FINI as u32, 0x1330 | thumb),
                ],
            )
            .build();
        // Deliberately non-executable host bytes: only plans may be produced.
        bytes.resize(0x400, 0);
        let memory = TargetMemory::default();
        let mut files = Source { bytes };
        let loaded = crate::load(
            LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
            LoadServices {
                sources: &mut files,
                images: &mut LocalRepository,
                memory,
                cache: &mut Cache::default(),
                observer: &mut (),
            },
            &mut RetainResources,
        )
        .unwrap();
        let owner = loaded.images().next().unwrap().instance_id();
        assert_eq!(loaded.startup().len(), 1);
        assert_eq!(loaded.fini().len(), 1);
        assert_eq!(loaded.rollback_fini(), loaded.fini());
        assert_eq!(loaded.startup()[0].owner(), owner);
        assert_eq!(loaded.startup()[0].function().get(), 0x100320 | thumb);
        assert_eq!(loaded.fini()[0].owner(), owner);
        assert_eq!(loaded.fini()[0].function().get(), 0x100330 | thumb);
        drop(loaded);
    }
}

fn separated_segments(profile: LoadProfile, fixed: bool) -> Vec<u8> {
    let mut bytes = builder(profile)
        .with_program_header(ProgramHeaderFixture {
            kind: 1,
            flags: 5,
            offset: 0,
            vaddr: TargetAddress::new(0x1000),
            filesz: 0x180,
            memsz: 0x180,
            align: 4,
        })
        .with_program_header(ProgramHeaderFixture {
            kind: 1,
            flags: 6,
            offset: 0x200,
            vaddr: TargetAddress::new(0x3000),
            filesz: 4,
            memsz: 0x20,
            align: 4,
        })
        .with_entry(0x1000 | u64::from(profile.entry_mode().is_thumb()))
        .build();
    if fixed {
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    }
    bytes.resize(0x204, 0);
    bytes[0x200..0x204].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    bytes
}

#[test]
fn image_layout_drives_sparse_backing_with_one_base_for_all_segments() {
    for profile in profiles() {
        for fixed in [false, true] {
            let memory = TargetMemory::default();
            let mut files = Source {
                bytes: separated_segments(profile, fixed),
            };
            let loaded = crate::load(
                LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
                LoadServices {
                    sources: &mut files,
                    images: &mut LocalRepository,
                    memory: memory.clone(),
                    cache: &mut Cache::default(),
                    observer: &mut (),
                },
                &mut RetainResources,
            )
            .unwrap();
            let allocation = memory.0.borrow().allocation.unwrap();
            let expected_base = if fixed { 0x1000 } else { 0x100000 };
            assert_eq!(allocation.base().get(), expected_base);
            assert_eq!(
                loaded.entry().unwrap().get(),
                expected_base | u64::from(profile.entry_mode().is_thumb())
            );
            {
                let state = memory.0.borrow();
                let layout = &state.layouts[0];
                assert_eq!(layout.request().size(), 0x2020);
                assert_eq!(layout.segments().len(), 2);
                assert_eq!(layout.segments()[0].offset().value(), 0);
                assert_eq!(
                    layout.segments()[0].permissions(),
                    MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE)
                );
                assert_eq!(layout.segments()[1].offset().value(), 0x2000);
                assert_eq!(layout.segments()[1].memory_size(), 0x20);
                assert_eq!(
                    layout.segments()[1].permissions(),
                    MemoryPermissions::READ.bitor(MemoryPermissions::WRITE)
                );
                assert_eq!(
                    state.segments.iter().map(|s| s.bytes.len()).sum::<usize>(),
                    0x1a0
                );
            }
            let mut data = [0xff; 0x20];
            memory
                .read(&allocation, AllocationOffset::new(0x2000), &mut data)
                .unwrap();
            assert_eq!(&data[..4], &[0x12, 0x34, 0x56, 0x78]);
            assert!(data[4..].iter().all(|byte| *byte == 0));
            // Logical gaps belong to the reservation but have no readable backing.
            memory
                .validate_range(&allocation, AllocationOffset::new(0x1000), 1)
                .unwrap();
            assert!(memory
                .read(&allocation, AllocationOffset::new(0x1000), &mut data[..1])
                .is_err());
            drop(loaded);
            let state = memory.0.borrow();
            assert!(state.allocation.is_none());
            assert!(state.segments.is_empty());
            assert_eq!(state.releases, 1);
        }
    }
}

#[test]
fn failed_segment_preparation_leaves_no_image_resources() {
    let profile = LoadProfile::riscv64();
    let memory = TargetMemory::default();
    memory.0.borrow_mut().fail_segment = Some(1);
    let mut files = Source {
        bytes: separated_segments(profile, false),
    };
    let error = crate::load(
        LoadRequest::executable(source(), profile, SessionLimits::DEFAULT),
        LoadServices {
            sources: &mut files,
            images: &mut LocalRepository,
            memory: memory.clone(),
            cache: &mut Cache::default(),
            observer: &mut (),
        },
        &mut RetainResources,
    )
    .err()
    .unwrap();
    assert_eq!(error.stage(), Some(crate::error::LoadStage::Allocate));
    let state = memory.0.borrow();
    assert!(state.allocation.is_none());
    assert!(state.segments.is_empty());
    assert!(state.layouts.is_empty());
    assert_eq!(
        state.aborts, 0,
        "failed preparation must clean up before returning Err"
    );
}

#[test]
fn image_layout_rejects_empty_overlapping_and_out_of_bounds_segments() {
    let request = AllocationRequest::new(Placement::Anywhere, 0x100, 4);
    let segment = |offset, size| {
        SegmentLayout::new(AllocationOffset::new(offset), size, MemoryPermissions::READ)
    };
    for (segments, kind) in [
        (alloc::vec![], crate::error::LoadErrorKind::IncorrectLayout),
        (
            alloc::vec![segment(0, 0)],
            crate::error::LoadErrorKind::IncorrectLayout,
        ),
        (
            alloc::vec![segment(0, 0x20), segment(0x10, 0x10)],
            crate::error::LoadErrorKind::IncorrectLayout,
        ),
        (
            alloc::vec![segment(0x40, 0x10), segment(0, 0x10)],
            crate::error::LoadErrorKind::IncorrectLayout,
        ),
        (
            alloc::vec![segment(0xf0, 0x20)],
            crate::error::LoadErrorKind::OutOfBounds,
        ),
        (
            alloc::vec![segment(u64::MAX, 2)],
            crate::error::LoadErrorKind::IntegerOverflow,
        ),
    ] {
        assert_eq!(
            ImageLayout::new(request, segments).unwrap_err().kind(),
            kind
        );
    }
    assert!(ImageLayout::new(
        request,
        alloc::vec![segment(0x10, 0x10), segment(0x40, 0x10)]
    )
    .is_ok());
}

#[test]
fn image_layout_validates_the_reservation_before_preparing_memory() {
    let segment = || {
        alloc::vec![SegmentLayout::new(
            AllocationOffset::new(0),
            4,
            MemoryPermissions::READ
        )]
    };
    let fixed = |start, len| Placement::Fixed(TargetRange::new(TargetAddress::new(start), len));
    for (request, kind) in [
        (
            AllocationRequest::new(Placement::Anywhere, 8, 0),
            crate::error::LoadErrorKind::InvalidAlignment,
        ),
        (
            AllocationRequest::new(Placement::Anywhere, 8, 3),
            crate::error::LoadErrorKind::InvalidAlignment,
        ),
        (
            AllocationRequest::new(Placement::Anywhere, 0, 4),
            crate::error::LoadErrorKind::IncorrectLayout,
        ),
        (
            AllocationRequest::new(fixed(0x1000, 4), 8, 4),
            crate::error::LoadErrorKind::IncorrectLayout,
        ),
        (
            AllocationRequest::new(fixed(0x1001, 8), 8, 4),
            crate::error::LoadErrorKind::IncorrectLayout,
        ),
        (
            AllocationRequest::new(fixed(u64::MAX - 3, 8), 8, 4),
            crate::error::LoadErrorKind::IntegerOverflow,
        ),
    ] {
        assert_eq!(
            ImageLayout::new(request, segment()).unwrap_err().kind(),
            kind
        );
    }
}
