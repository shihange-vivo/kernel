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

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use goblin::elf::{
    dynamic::{
        DF_TEXTREL, DT_DEBUG, DT_FLAGS, DT_FLAGS_1, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTREL,
        DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT, DT_RELSZ, DT_TEXTREL,
    },
    header::{EI_CLASS, EI_DATA, ELFCLASS32, ELFDATA2MSB, EM_ARM, EM_RISCV, ET_DYN, ET_EXEC},
    reloc::{R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_RELATIVE},
    Elf,
};

use self::fixture::ElfFixtureBuilder;
use crate::{
    AllocationId, AllocationOwnership, AllocationRequest, ArmRelocator, ArtifactProfile,
    ArtifactRequest, CodeCache, ElfClass, ElfReader, Endian, ErrorContext, ExpectedElfType,
    ImageAllocation, ImageLoadTransaction, ImageLoader, ImageMemory, LoadError, LoadErrorKind,
    LoadLimits, LoadResult, LoadStage, MemoryPermissions, Placement, PlannedArtifact,
    ProtectionLevel, RelocationAddend, Riscv64Relocator, RuntimeFeaturePolicy, SliceElfReader,
    TargetAddr, TargetLocation,
};
use goblin::elf::program_header::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_TLS,
};

fn riscv64_request() -> ArtifactRequest {
    ArtifactRequest::new(
        ExpectedElfType::Dyn,
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

#[derive(Clone, Copy, Debug)]
enum InjectedReadFailure {
    ShortRead,
    Io,
}

#[derive(Debug, Default)]
struct ReaderLog {
    calls: Cell<usize>,
    reads: RefCell<std::vec::Vec<(u64, usize)>>,
}

#[derive(Debug)]
struct RecordingReader<'a> {
    inner: SliceElfReader<'a>,
    log: Rc<ReaderLog>,
    failure: Option<(usize, InjectedReadFailure)>,
}

impl<'a> RecordingReader<'a> {
    fn new(
        bytes: &'a [u8],
        failure: Option<(usize, InjectedReadFailure)>,
    ) -> (Self, Rc<ReaderLog>) {
        let log = Rc::new(ReaderLog::default());
        (
            Self {
                inner: SliceElfReader::new(bytes),
                log: Rc::clone(&log),
                failure,
            },
            log,
        )
    }
}

impl ElfReader for RecordingReader<'_> {
    fn len(&self) -> LoadResult<u64> {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let call = self.log.calls.get();
        self.log.calls.set(call + 1);
        self.log.reads.borrow_mut().push((offset, dst.len()));
        if let Some((_, failure)) = self.failure.filter(|(index, _)| *index == call) {
            return Err(LoadError::new(
                LoadStage::Read,
                match failure {
                    InjectedReadFailure::ShortRead => LoadErrorKind::OutOfBounds,
                    InjectedReadFailure::Io => LoadErrorKind::Io,
                },
                ErrorContext::FileRange {
                    offset,
                    len: dst.len() as u64,
                    file_len: self.inner.len()?,
                },
            ));
        }
        self.inner.read_exact_at(offset, dst)
    }
}

#[test]
fn admit_records_read_at_requests_and_propagates_each_reader_failure() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    for (failure, expected_kind) in [
        (InjectedReadFailure::ShortRead, LoadErrorKind::OutOfBounds),
        (InjectedReadFailure::Io, LoadErrorKind::Io),
    ] {
        for failure_call in 0..2 {
            let (reader, log) = RecordingReader::new(&bytes, Some((failure_call, failure)));
            let error = ImageLoader::new()
                .admit(reader, riscv64_request())
                .unwrap_err();
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(log.calls.get(), failure_call + 1);
            assert_eq!(log.reads.borrow().len(), failure_call + 1);
        }
    }

    let (reader, log) = RecordingReader::new(&bytes, None);
    ImageLoader::new().admit(reader, riscv64_request()).unwrap();
    assert_eq!(log.reads.borrow().as_slice(), [(0, 16), (0, 64)]);
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
        ExpectedElfType::Dyn,
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

    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_program_header_table(u64::MAX - 20, 1)
        .build();
    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap_err()
            .kind(),
        LoadErrorKind::IntegerOverflow
    );
}

#[test]
fn admit_enforces_file_and_program_header_limits() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    let file_limit_request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
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
        ExpectedElfType::Dyn,
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

#[test]
fn plan_supports_nonzero_virtual_bases_and_segment_gaps() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1010)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0, 0x3000, 0, 0x100, PF_R | PF_W, 0x1000)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&bytes), riscv64_request())
        .unwrap();
    let planned = loader.plan(admitted).unwrap();

    assert_eq!(planned.layout().aligned_min_vaddr().get(), 0x1000);
    assert_eq!(planned.layout().aligned_max_vaddr().get(), 0x4000);
    assert_eq!(planned.layout().image_span(), 0x3000);
    assert_eq!(
        planned
            .layout()
            .load_bias_for(crate::TargetAddr::new(0x8000), ExpectedElfType::Dyn)
            .unwrap()
            .get(),
        0x7000
    );
    assert!(planned
        .layout()
        .locate_vaddr_range(
            crate::TargetAddr::new(0x1010),
            1,
            crate::MemoryPermissions::EXECUTE
        )
        .is_ok());
    assert!(planned
        .layout()
        .locate_vaddr_range(
            crate::TargetAddr::new(0x2000),
            1,
            crate::MemoryPermissions::READ
        )
        .is_err());
}

#[test]
fn plan_preserves_arm_thumb_entry_while_validating_its_canonical_address() {
    let bytes = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN)
        .set_entry(0x1001)
        .add_program_header(PT_LOAD, 0, 0x1000, 52, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::new(ElfClass::Elf32, Endian::Little, EM_ARM),
        LoadLimits::default(),
    );
    let loader = ImageLoader::new();
    let admitted = loader.admit(SliceElfReader::new(&bytes), request).unwrap();
    let planned = loader.plan(admitted).unwrap();

    assert_eq!(planned.layout().entry_vaddr().get(), 0x1001);
    assert_eq!(planned.layout().canonical_entry_vaddr().get(), 0x1000);
}

#[test]
fn plan_rejects_invalid_segment_shapes_and_permissions() {
    let cases = [
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_entry(0x1000)
            .add_program_header(PT_LOAD, 0, 0x1000, 64, 32, PF_R | PF_X, 1)
            .build(),
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_entry(0x1000)
            .add_program_header(PT_LOAD, 0, 0x1000, 64, 64, PF_R | PF_X, 3)
            .build(),
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_entry(0x1000)
            .add_program_header(PT_LOAD, 1, 0x1000, 64, 64, PF_R | PF_X, 0x1000)
            .build(),
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_entry(0x1000)
            .add_program_header(PT_LOAD, 0, 0x1000, 64, 64, PF_R | PF_W | PF_X, 1)
            .build(),
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_entry(0x1000)
            .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x200, PF_R | PF_X, 1)
            .add_program_header(PT_LOAD, 0, 0x1100, 0, 0x200, PF_R | PF_W, 1)
            .build(),
    ];

    for bytes in cases {
        let loader = ImageLoader::new();
        let admitted = loader
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap();
        assert!(loader.plan(admitted).is_err());
    }
}

#[test]
fn plan_rejects_virtual_range_and_alignment_overflow() {
    let range_overflow = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(u64::MAX - 0x10)
        .add_program_header(PT_LOAD, 0, u64::MAX - 0x10, 0, 0x100, PF_R | PF_X, 1)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&range_overflow), riscv64_request())
        .unwrap();
    assert_eq!(
        loader.plan(admitted).unwrap_err().kind(),
        LoadErrorKind::IntegerOverflow
    );

    let alignment_overflow = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 0, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0, u64::MAX - 0x7ff, 0, 0x100, PF_R | PF_W, 1)
        .build();
    let admitted = loader
        .admit(SliceElfReader::new(&alignment_overflow), riscv64_request())
        .unwrap();
    assert_eq!(
        loader.plan(admitted).unwrap_err().kind(),
        LoadErrorKind::IntegerOverflow
    );
}

#[test]
fn plan_rejects_missing_or_non_executable_entries() {
    let no_load = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN).build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&no_load), riscv64_request())
        .unwrap();
    assert_eq!(
        loader.plan(admitted).unwrap_err().kind(),
        LoadErrorKind::BadElf
    );

    let entry_in_gap = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x2000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 1)
        .add_program_header(PT_LOAD, 0, 0x3000, 0, 0x100, PF_R | PF_W, 1)
        .build();
    let admitted = loader
        .admit(SliceElfReader::new(&entry_in_gap), riscv64_request())
        .unwrap();
    assert_eq!(
        loader.plan(admitted).unwrap_err().kind(),
        LoadErrorKind::PermissionConflict
    );
}

#[test]
fn plan_enforces_image_span_and_segment_count_limits() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0, 0x9000, 0, 0x100, PF_R | PF_W, 0x1000)
        .build();
    for limits in [
        LoadLimits::new(1024, 16).with_image_limits(1, u64::MAX),
        LoadLimits::new(1024, 16).with_image_limits(16, 0x1000),
    ] {
        let request = ArtifactRequest::new(
            ExpectedElfType::Dyn,
            ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
            limits,
        );
        let loader = ImageLoader::new();
        let admitted = loader.admit(SliceElfReader::new(&bytes), request).unwrap();
        assert_eq!(
            loader.plan(admitted).unwrap_err().kind(),
            LoadErrorKind::ResourceLimit
        );
    }
}

#[derive(Debug)]
struct FakeMemory {
    allocation: Option<ImageAllocation>,
    fail_allocate: bool,
    requests: std::vec::Vec<AllocationRequest>,
    releases: std::vec::Vec<AllocationId>,
    bytes: std::vec::Vec<u8>,
    writes: std::vec::Vec<(TargetLocation, usize)>,
    zeros: std::vec::Vec<(TargetLocation, u64)>,
    reads: RefCell<std::vec::Vec<(TargetLocation, usize)>>,
    protects: std::vec::Vec<(TargetLocation, u64, MemoryPermissions)>,
    fail_write_at: Option<usize>,
    fail_zero_at: Option<usize>,
    fail_read_at: Option<usize>,
    fail_protect_at: Option<usize>,
}

impl FakeMemory {
    fn returning(allocation: ImageAllocation) -> Self {
        let len = usize::try_from(allocation.len()).unwrap();
        Self {
            allocation: Some(allocation),
            fail_allocate: false,
            requests: std::vec::Vec::new(),
            releases: std::vec::Vec::new(),
            bytes: std::vec![0xa5; len],
            writes: std::vec::Vec::new(),
            zeros: std::vec::Vec::new(),
            reads: RefCell::new(std::vec::Vec::new()),
            protects: std::vec::Vec::new(),
            fail_write_at: None,
            fail_zero_at: None,
            fail_read_at: None,
            fail_protect_at: None,
        }
    }

    fn failing() -> Self {
        Self {
            allocation: None,
            fail_allocate: true,
            requests: std::vec::Vec::new(),
            releases: std::vec::Vec::new(),
            bytes: std::vec::Vec::new(),
            writes: std::vec::Vec::new(),
            zeros: std::vec::Vec::new(),
            reads: RefCell::new(std::vec::Vec::new()),
            protects: std::vec::Vec::new(),
            fail_write_at: None,
            fail_zero_at: None,
            fail_read_at: None,
            fail_protect_at: None,
        }
    }
}

impl ImageMemory for FakeMemory {
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<ImageAllocation> {
        self.requests.push(*request);
        if self.fail_allocate {
            return Err(LoadError::new(
                LoadStage::Allocate,
                LoadErrorKind::OutOfMemory,
                ErrorContext::None,
            ));
        }
        Ok(self.allocation.expect("test allocation must be configured"))
    }

    fn release(&mut self, allocation: AllocationId) {
        self.releases.push(allocation);
    }

    fn validate_access(
        &self,
        location: TargetLocation,
        len: u64,
        _permissions: MemoryPermissions,
    ) -> LoadResult<()> {
        let allocation = self
            .allocation
            .ok_or_else(|| fake_access_error(location, len))?;
        let valid = allocation.id() == location.allocation()
            && location
                .offset()
                .checked_add(len)
                .is_some_and(|end| end <= allocation.len());
        if valid {
            Ok(())
        } else {
            Err(fake_access_error(location, len))
        }
    }

    fn write(&mut self, location: TargetLocation, data: &[u8]) -> LoadResult<()> {
        self.validate_access(location, data.len() as u64, MemoryPermissions::WRITE)?;
        if self.fail_write_at == Some(self.writes.len()) {
            return Err(fake_access_error(location, data.len() as u64));
        }
        let start = location.offset() as usize;
        self.bytes[start..start + data.len()].copy_from_slice(data);
        self.writes.push((location, data.len()));
        Ok(())
    }

    fn zero(&mut self, location: TargetLocation, len: u64) -> LoadResult<()> {
        self.validate_access(location, len, MemoryPermissions::WRITE)?;
        if self.fail_zero_at == Some(self.zeros.len()) {
            return Err(fake_access_error(location, len));
        }
        let start = location.offset() as usize;
        self.bytes[start..start + len as usize].fill(0);
        self.zeros.push((location, len));
        Ok(())
    }

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> LoadResult<()> {
        self.validate_access(location, dst.len() as u64, MemoryPermissions::READ)?;
        let read_index = self.reads.borrow().len();
        if self.fail_read_at == Some(read_index) {
            return Err(fake_access_error(location, dst.len() as u64));
        }
        let start = location.offset() as usize;
        dst.copy_from_slice(&self.bytes[start..start + dst.len()]);
        self.reads.borrow_mut().push((location, dst.len()));
        Ok(())
    }

    fn protect(
        &mut self,
        location: TargetLocation,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<ProtectionLevel> {
        self.validate_access(location, len, permissions)?;
        if self.fail_protect_at == Some(self.protects.len()) {
            return Err(fake_access_error(location, len));
        }
        self.protects.push((location, len, permissions));
        Ok(ProtectionLevel::LogicalOnly)
    }
}

fn fake_access_error(location: TargetLocation, len: u64) -> LoadError {
    LoadError::new(
        LoadStage::Map,
        LoadErrorKind::Backend,
        ErrorContext::MemoryAccess {
            allocation: location.allocation(),
            offset: location.offset(),
            len,
        },
    )
}

fn planned_image<'a>(
    bytes: &'a [u8],
    expected_elf_type: ExpectedElfType,
) -> PlannedArtifact<SliceElfReader<'a>> {
    let request = ArtifactRequest::new(
        expected_elf_type,
        ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
        LoadLimits::default(),
    );
    let loader = ImageLoader::new();
    let admitted = loader.admit(SliceElfReader::new(bytes), request).unwrap();
    loader.plan(admitted).unwrap()
}

#[test]
fn reserve_uses_movable_placement_for_any_et_dyn_image() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1010)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0, 0x3000, 0, 0x100, PF_R | PF_W, 0x1000)
        .build();
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(7);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        assert_eq!(reserved.load_bias().get(), 0x7000);
        transaction
    };
    transaction.disarm_for_test();

    assert_eq!(memory.requests.len(), 1);
    assert_eq!(memory.requests[0].placement(), Placement::Anywhere);
    assert_eq!(memory.requests[0].size(), 0x3000);
    assert!(memory.releases.is_empty());
}

#[test]
fn reserve_uses_fixed_placement_only_for_et_exec() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_EXEC)
        .set_entry(0x1010)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let planned = planned_image(&bytes, ExpectedElfType::Exec);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(8),
        TargetAddr::new(0x1000),
        0x1000,
        0x1000,
        AllocationOwnership::BorrowedFixed,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        assert_eq!(reserved.load_bias().get(), 0);
        transaction
    };
    transaction.disarm_for_test();

    assert_eq!(
        memory.requests[0].placement(),
        Placement::Fixed(crate::TargetRange::new(TargetAddr::new(0x1000), 0x1000))
    );
    assert!(memory.releases.is_empty());
}

#[test]
fn reserve_releases_a_backend_allocation_that_fails_validation() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let invalid_allocations = [
        ImageAllocation::new(
            AllocationId::new(90),
            TargetAddr::new(0x8000),
            0x800,
            0x1000,
            AllocationOwnership::Owned,
        ),
        ImageAllocation::new(
            AllocationId::new(91),
            TargetAddr::new(0x8001),
            0x1000,
            0x1000,
            AllocationOwnership::Owned,
        ),
        ImageAllocation::new(
            AllocationId::new(92),
            TargetAddr::new(0x8000),
            0x1000,
            1,
            AllocationOwnership::Owned,
        ),
        ImageAllocation::new(
            AllocationId::new(93),
            TargetAddr::new(0x8000),
            0x1000,
            0x1000,
            AllocationOwnership::BorrowedFixed,
        ),
    ];

    for allocation in invalid_allocations {
        let planned = planned_image(&bytes, ExpectedElfType::Dyn);
        let mut memory = FakeMemory::returning(allocation);
        {
            let mut transaction = ImageLoadTransaction::new(&mut memory);
            let error = ImageLoader::new()
                .reserve(planned, &mut transaction)
                .unwrap_err();
            assert_eq!(error.kind(), LoadErrorKind::Backend);
        }
        assert_eq!(memory.releases, [allocation.id()]);
    }

    let exec = ElfFixtureBuilder::elf64(EM_RISCV, ET_EXEC)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let planned = planned_image(&exec, ExpectedElfType::Exec);
    let allocation = ImageAllocation::new(
        AllocationId::new(94),
        TargetAddr::new(0x2000),
        0x1000,
        0x1000,
        AllocationOwnership::BorrowedFixed,
    );
    let mut memory = FakeMemory::returning(allocation);
    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        assert!(ImageLoader::new()
            .reserve(planned, &mut transaction)
            .is_err());
    }
    assert_eq!(memory.releases, [allocation.id()]);
}

#[test]
fn reserve_does_not_release_when_allocation_itself_fails() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let mut memory = FakeMemory::failing();

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let error = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::OutOfMemory);
    }

    assert!(memory.releases.is_empty());
}

#[test]
fn memory_mapper_allocates_fallibly_and_releases_owned_storage() {
    let request = AllocationRequest::new(Placement::Anywhere, 0x2000, 0x1000);
    let mut mapper = crate::MemoryMapper::new(None);

    let allocation = ImageMemory::allocate_image(&mut mapper, &request).unwrap();
    assert_eq!(allocation.ownership(), AllocationOwnership::Owned);
    assert_eq!(allocation.target_base().get() % 0x1000, 0);
    assert_eq!(allocation.len(), 0x2000);

    ImageMemory::release(&mut mapper, allocation.id());
    assert!(mapper.real_start().is_err());
}

#[test]
fn memory_mapper_rejects_unauthorized_fixed_placement() {
    let request = AllocationRequest::new(
        Placement::Fixed(crate::TargetRange::new(TargetAddr::new(0x1000), 0x1000)),
        0x1000,
        0x1000,
    );
    let mut mapper = crate::MemoryMapper::new(Some(&[]));

    let error = ImageMemory::allocate_image(&mut mapper, &request).unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::Backend);
}

fn image_with_bss_and_gap(elf_type: u16) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let text: std::vec::Vec<u8> = (0..700).map(|value| value as u8).collect();
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, elf_type)
        .set_entry(0x1010)
        .add_program_header(
            PT_LOAD,
            0x1000,
            0x1000,
            text.len() as u64,
            0x800,
            PF_R | PF_X,
            0x1000,
        )
        .add_program_header(PT_LOAD, 0x2000, 0x3000, 4, 0x100, PF_R | PF_W, 0x1000)
        .write_bytes(0x1000, &text)
        .write_bytes(0x2000, &[1, 2, 3, 4])
        .build();
    (bytes, text)
}

#[test]
fn copy_and_zero_initializes_owned_et_dyn_memory_in_chunks() {
    let (bytes, text) = image_with_bss_and_gap(ET_DYN);
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(10),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        assert_eq!(mapped.entry().get(), 0x8010);
        assert_eq!(mapped.regions()[0].runtime_range().start().get(), 0x8000);
        assert_eq!(mapped.regions()[1].runtime_range().start().get(), 0xa000);
        assert!(mapped
            .locate_vaddr(TargetAddr::new(0x2000), 1, MemoryPermissions::READ)
            .is_err());
        transaction
    };
    transaction.disarm_for_test();

    assert_eq!(&memory.bytes[..text.len()], text.as_slice());
    assert!(memory.bytes[text.len()..0x2000]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(&memory.bytes[0x2000..0x2004], &[1, 2, 3, 4]);
    assert!(memory.bytes[0x2004..].iter().all(|byte| *byte == 0));
    assert_eq!(
        memory.zeros,
        [(TargetLocation::new(AllocationId::new(10), 0), 0x3000)]
    );
    assert_eq!(memory.writes.len(), 3);
    assert_eq!(memory.writes[0].1, 512);
    assert!(memory.releases.is_empty());
}

#[test]
fn copy_and_zero_preserves_fixed_et_exec_gaps() {
    let (bytes, text) = image_with_bss_and_gap(ET_EXEC);
    let planned = planned_image(&bytes, ExpectedElfType::Exec);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(11),
        TargetAddr::new(0x1000),
        0x3000,
        0x1000,
        AllocationOwnership::BorrowedFixed,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        transaction
    };
    transaction.disarm_for_test();

    assert_eq!(&memory.bytes[..text.len()], text.as_slice());
    assert!(memory.bytes[text.len()..0x800]
        .iter()
        .all(|byte| *byte == 0));
    assert!(memory.bytes[0x800..0x2000].iter().all(|byte| *byte == 0xa5));
    assert_eq!(&memory.bytes[0x2000..0x2004], &[1, 2, 3, 4]);
    assert!(memory.bytes[0x2004..0x2100].iter().all(|byte| *byte == 0));
    assert!(memory.bytes[0x2100..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(memory.zeros.len(), 2);
}

struct FaultingReader<'a> {
    inner: SliceElfReader<'a>,
    fail_at: u64,
}

impl<'a> FaultingReader<'a> {
    fn new(bytes: &'a [u8], fail_at: u64) -> Self {
        Self {
            inner: SliceElfReader::new(bytes),
            fail_at,
        }
    }
}

impl ElfReader for FaultingReader<'_> {
    fn len(&self) -> LoadResult<u64> {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        if offset >= self.fail_at {
            return Err(LoadError::new(
                LoadStage::Read,
                LoadErrorKind::Io,
                ErrorContext::FileRange {
                    offset,
                    len: dst.len() as u64,
                    file_len: self.inner.len()?,
                },
            ));
        }
        self.inner.read_exact_at(offset, dst)
    }
}

#[test]
fn copy_failure_rolls_back_the_owned_allocation() {
    let (bytes, _) = image_with_bss_and_gap(ET_DYN);
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
        LoadLimits::default(),
    );
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(FaultingReader::new(&bytes, 0x1000), request)
        .unwrap();
    let planned = loader.plan(admitted).unwrap();
    let allocation_id = AllocationId::new(12);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = loader.reserve(planned, &mut transaction).unwrap();
        let error = loader
            .copy_and_zero(reserved, &mut transaction)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::Io);
    }

    assert_eq!(memory.releases, [allocation_id]);
}

#[test]
fn copy_propagates_each_chunk_read_failure_and_rolls_back() {
    let (bytes, _) = image_with_bss_and_gap(ET_DYN);
    for failure_call in 4..7 {
        let (reader, log) =
            RecordingReader::new(&bytes, Some((failure_call, InjectedReadFailure::Io)));
        let loader = ImageLoader::new();
        let admitted = loader.admit(reader, riscv64_request()).unwrap();
        let planned = loader.plan(admitted).unwrap();
        let allocation_id = AllocationId::new(120 + failure_call as u32);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));

        {
            let mut transaction = ImageLoadTransaction::new(&mut memory);
            let reserved = loader.reserve(planned, &mut transaction).unwrap();
            let error = loader
                .copy_and_zero(reserved, &mut transaction)
                .unwrap_err();
            assert_eq!(error.kind(), LoadErrorKind::Io);
        }

        assert_eq!(log.calls.get(), failure_call + 1);
        assert_eq!(memory.releases, [allocation_id]);
    }
}

#[test]
fn copy_rolls_back_at_every_zero_and_write_failure() {
    let (bytes, _) = image_with_bss_and_gap(ET_DYN);

    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let zero_allocation = AllocationId::new(130);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        zero_allocation,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    memory.fail_zero_at = Some(0);
    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        assert!(ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .is_err());
    }
    assert_eq!(memory.releases, [zero_allocation]);
    assert!(memory.writes.is_empty());

    for failure_call in 0..3 {
        let planned = planned_image(&bytes, ExpectedElfType::Dyn);
        let allocation_id = AllocationId::new(131 + failure_call as u32);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        memory.fail_write_at = Some(failure_call);
        {
            let mut transaction = ImageLoadTransaction::new(&mut memory);
            let reserved = ImageLoader::new()
                .reserve(planned, &mut transaction)
                .unwrap();
            assert!(ImageLoader::new()
                .copy_and_zero(reserved, &mut transaction)
                .is_err());
        }
        assert_eq!(memory.writes.len(), failure_call);
        assert_eq!(memory.releases, [allocation_id]);
    }
}

fn image_with_dynamic_entries(entries: &[(u64, u64)], relocation_info: u64) -> std::vec::Vec<u8> {
    image_with_dynamic_relocation(entries, 0x3200, relocation_info, -0x20)
}

fn image_with_dynamic_relocation(
    entries: &[(u64, u64)],
    target: u64,
    relocation_info: u64,
    addend: i64,
) -> std::vec::Vec<u8> {
    ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0x2000, 0x3000, 0x118, 0x300, PF_R | PF_W, 0x1000)
        .add_program_header(
            PT_DYNAMIC,
            0x2000,
            0x3000,
            (entries.len() * 16) as u64,
            (entries.len() * 16) as u64,
            PF_R | PF_W,
            8,
        )
        .write_dynamic(0x2000, entries)
        .write_rela64(0x2100, &[(target, relocation_info, addend)])
        .build()
}

#[test]
fn decode_runtime_normalizes_bounded_rela_metadata() {
    let entries = [
        (DT_RELA, 0x3100),
        (DT_RELASZ, 24),
        (DT_RELAENT, 24),
        (DT_FLAGS_1, 0),
        (DT_NULL, 0),
    ];
    let bytes = image_with_dynamic_entries(&entries, 3);
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(13),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        let relocation = runtime.metadata().relocations()[0];
        assert_eq!(runtime.metadata().relocations().len(), 1);
        assert_eq!(relocation.offset().get(), 0x3200);
        assert_eq!(relocation.raw_type(), 3);
        assert_eq!(relocation.symbol_index(), 0);
        assert_eq!(relocation.addend(), RelocationAddend::Explicit(-0x20));
        transaction
    };
    transaction.disarm_for_test();
    assert!(memory.releases.is_empty());
}

#[test]
fn decode_runtime_rejects_dependencies_instead_of_classifying_et_dyn() {
    let entries = [(DT_NEEDED, 1), (DT_NULL, 0)];
    let bytes = image_with_dynamic_entries(&entries, 3);
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(14);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let error = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
    }
    assert_eq!(memory.releases, [allocation_id]);
}

#[test]
fn decode_runtime_requires_dt_null_and_enforces_entry_limits() {
    for (entries, limits, expected_kind) in [
        (
            std::vec![(DT_DEBUG, 0)],
            LoadLimits::default(),
            LoadErrorKind::BadElf,
        ),
        (
            std::vec![(DT_DEBUG, 0), (DT_FLAGS_1, 0), (DT_NULL, 0)],
            LoadLimits::default().with_runtime_limits(1, 16),
            LoadErrorKind::ResourceLimit,
        ),
    ] {
        let bytes = image_with_dynamic_entries(&entries, 3);
        let request = ArtifactRequest::new(
            ExpectedElfType::Dyn,
            ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
            limits,
        );
        let loader = ImageLoader::new();
        let admitted = loader.admit(SliceElfReader::new(&bytes), request).unwrap();
        let planned = loader.plan(admitted).unwrap();
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            AllocationId::new(15),
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = loader.reserve(planned, &mut transaction).unwrap();
        let mapped = loader.copy_and_zero(reserved, &mut transaction).unwrap();
        let error = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap_err();
        assert_eq!(error.kind(), expected_kind);
    }
}

#[test]
fn decode_runtime_rejects_symbol_based_relocations_in_phase0() {
    let entries = [
        (DT_RELA, 0x3100),
        (DT_RELASZ, 24),
        (DT_RELAENT, 24),
        (DT_NULL, 0),
    ];
    let bytes = image_with_dynamic_entries(&entries, (1_u64 << 32) | 3);
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(16),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = ImageLoader::new()
        .reserve(planned, &mut transaction)
        .unwrap();
    let mapped = ImageLoader::new()
        .copy_and_zero(reserved, &mut transaction)
        .unwrap();

    let error = mapped
        .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
        .unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
}

fn decode_runtime_for_test(entries: &[(u64, u64)], limits: LoadLimits) -> LoadResult<usize> {
    let bytes = image_with_dynamic_entries(entries, 3);
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::new(ElfClass::Elf64, Endian::Little, EM_RISCV),
        limits,
    );
    let loader = ImageLoader::new();
    let admitted = loader.admit(SliceElfReader::new(&bytes), request)?;
    let planned = loader.plan(admitted)?;
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(160),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = loader.reserve(planned, &mut transaction)?;
    let mapped = loader.copy_and_zero(reserved, &mut transaction)?;
    let runtime = mapped.decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)?;
    let relocation_count = runtime.metadata().relocations().len();
    transaction.disarm_for_test();
    Ok(relocation_count)
}

#[test]
fn decode_runtime_rejects_malformed_relocation_descriptors() {
    let malformed: &[&[(u64, u64)]] = &[
        &[
            (DT_RELA, 0x3100),
            (DT_RELA, 0x3100),
            (DT_RELASZ, 24),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ],
        &[(DT_RELASZ, 24), (DT_RELAENT, 24), (DT_NULL, 0)],
        &[(DT_RELA, 0x3100), (DT_RELAENT, 24), (DT_NULL, 0)],
        &[(DT_RELA, 0x3100), (DT_RELASZ, 24), (DT_NULL, 0)],
        &[
            (DT_RELA, 0x3100),
            (DT_RELASZ, 24),
            (DT_RELAENT, 16),
            (DT_NULL, 0),
        ],
        &[
            (DT_RELA, 0x3100),
            (DT_RELASZ, 25),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ],
    ];
    for entries in malformed {
        assert_eq!(
            decode_runtime_for_test(entries, LoadLimits::default())
                .unwrap_err()
                .kind(),
            LoadErrorKind::BadElf
        );
    }
}

#[test]
fn decode_runtime_rejects_relocation_tables_outside_readable_segments() {
    for address in [0x2000, 0x32f0] {
        let entries = [
            (DT_RELA, address),
            (DT_RELASZ, 24),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ];
        assert_eq!(
            decode_runtime_for_test(&entries, LoadLimits::default())
                .unwrap_err()
                .kind(),
            LoadErrorKind::OutOfBounds
        );
    }

    assert_eq!(
        decode_runtime_for_test(
            &rela_dynamic_entries(),
            LoadLimits::default().with_runtime_limits(16, 0),
        )
        .unwrap_err()
        .kind(),
        LoadErrorKind::ResourceLimit
    );
}

#[test]
fn phase0_policy_rejects_every_unsupported_dynamic_feature() {
    const DT_RELR_FOR_TEST: u64 = 36;
    for (tag, value) in [
        (DT_NEEDED, 1),
        (DT_TEXTREL, 0),
        (DT_JMPREL, 0x3100),
        (DT_PLTREL, DT_RELA),
        (DT_RELR_FOR_TEST, 0x3100),
        (DT_FLAGS, DF_TEXTREL),
        (0x6fff_f123, 0),
    ] {
        let entries = [(tag, value), (DT_NULL, 0)];
        assert_eq!(
            decode_runtime_for_test(&entries, LoadLimits::default())
                .unwrap_err()
                .kind(),
            LoadErrorKind::UnsupportedByProfile
        );
    }
}

#[test]
fn images_without_pt_dynamic_have_empty_runtime_metadata() {
    let (bytes, _) = image_with_bss_and_gap(ET_EXEC);
    let planned = planned_image(&bytes, ExpectedElfType::Exec);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(161),
        TargetAddr::new(0x1000),
        0x3000,
        0x1000,
        AllocationOwnership::BorrowedFixed,
    ));
    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = ImageLoader::new()
        .reserve(planned, &mut transaction)
        .unwrap();
    let mapped = ImageLoader::new()
        .copy_and_zero(reserved, &mut transaction)
        .unwrap();
    let runtime = mapped
        .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
        .unwrap();
    assert!(runtime.metadata().relocations().is_empty());
    transaction.disarm_for_test();
}

fn rela_dynamic_entries() -> [(u64, u64); 4] {
    [
        (DT_RELA, 0x3100),
        (DT_RELASZ, 24),
        (DT_RELAENT, 24),
        (DT_NULL, 0),
    ]
}

#[test]
fn riscv64_relocator_applies_load_bias_plus_explicit_addend() {
    let bytes = image_with_dynamic_entries(&rela_dynamic_entries(), 3);
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(17);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        let relocated = runtime
            .relocate(&mut transaction, &Riscv64Relocator)
            .unwrap();
        assert_eq!(relocated.metadata().relocations().len(), 1);
        transaction
    };
    transaction.disarm_for_test();

    assert_eq!(
        u64::from_le_bytes(memory.bytes[0x2200..0x2208].try_into().unwrap()),
        0x6fe0
    );
    assert!(memory.releases.is_empty());
}

#[test]
fn riscv64_relocator_rejects_unknown_types_before_writing() {
    let bytes = image_with_dynamic_entries(&rela_dynamic_entries(), 99);
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(18);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        let error = runtime
            .relocate(&mut transaction, &Riscv64Relocator)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
    }

    assert_eq!(&memory.bytes[0x2200..0x2208], &[0; 8]);
    assert_eq!(memory.releases, [allocation_id]);
}

#[test]
fn riscv64_relocator_checks_target_alignment_permissions_and_overflow() {
    for (target, addend, expected_kind) in [
        (0x3201, 0, LoadErrorKind::InvalidAlignment),
        (0x1000, 0, LoadErrorKind::OutOfBounds),
        (0x3200, i64::MIN, LoadErrorKind::IntegerOverflow),
    ] {
        let bytes = image_with_dynamic_relocation(&rela_dynamic_entries(), target, 3, addend);
        let planned = planned_image(&bytes, ExpectedElfType::Dyn);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            AllocationId::new(19),
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        let error = runtime
            .relocate(&mut transaction, &Riscv64Relocator)
            .unwrap_err();
        assert_eq!(error.kind(), expected_kind);
    }
}

fn arm32_rel_image(implicit_addend: u32) -> std::vec::Vec<u8> {
    arm32_rel_image_at(implicit_addend, 0x3200)
}

fn arm32_rel_image_at(implicit_addend: u32, target: u32) -> std::vec::Vec<u8> {
    let entries = [
        (DT_REL, 0x3100),
        (DT_RELSZ, 8),
        (DT_RELENT, 8),
        (DT_NULL, 0),
    ];
    ElfFixtureBuilder::elf32(EM_ARM, ET_DYN)
        .set_entry(0x1001)
        .add_program_header(PT_LOAD, 0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0x2000, 0x3000, 0x204, 0x300, PF_R | PF_W, 0x1000)
        .add_program_header(
            PT_DYNAMIC,
            0x2000,
            0x3000,
            (entries.len() * 8) as u64,
            (entries.len() * 8) as u64,
            PF_R | PF_W,
            4,
        )
        .write_dynamic(0x2000, &entries)
        .write_rel32(0x2100, &[(target, R_ARM_RELATIVE)])
        .write_bytes(0x2200, &implicit_addend.to_le_bytes())
        .build()
}

fn planned_arm32<'a>(bytes: &'a [u8]) -> PlannedArtifact<SliceElfReader<'a>> {
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::new(ElfClass::Elf32, Endian::Little, EM_ARM),
        LoadLimits::default(),
    );
    let loader = ImageLoader::new();
    let admitted = loader.admit(SliceElfReader::new(bytes), request).unwrap();
    loader.plan(admitted).unwrap()
}

#[test]
fn arm_relocator_applies_load_bias_to_an_implicit_rel_addend() {
    let bytes = arm32_rel_image(0x1235);
    let planned = planned_arm32(&bytes);
    let allocation_id = AllocationId::new(20);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    let transaction = {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        assert_eq!(mapped.entry().get(), 0x8001);
        assert_eq!(mapped.canonical_entry().get(), 0x8000);
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        assert_eq!(
            runtime.metadata().relocations()[0].addend(),
            RelocationAddend::Implicit
        );
        runtime.relocate(&mut transaction, &ArmRelocator).unwrap();
        transaction
    };
    transaction.disarm_for_test();

    assert_eq!(
        u32::from_le_bytes(memory.bytes[0x2200..0x2204].try_into().unwrap()),
        0x8235
    );
    assert!(memory.releases.is_empty());
}

#[test]
fn arm_relocator_rejects_symbol_relocations_before_writing() {
    for raw_type in [R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, 0xff] {
        let entries = [
            (DT_REL, 0x3100),
            (DT_RELSZ, 8),
            (DT_RELENT, 8),
            (DT_NULL, 0),
        ];
        let bytes = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN)
            .set_entry(0x1001)
            .add_program_header(PT_LOAD, 0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X, 0x1000)
            .add_program_header(PT_LOAD, 0x2000, 0x3000, 0x204, 0x300, PF_R | PF_W, 0x1000)
            .add_program_header(
                PT_DYNAMIC,
                0x2000,
                0x3000,
                (entries.len() * 8) as u64,
                (entries.len() * 8) as u64,
                PF_R | PF_W,
                4,
            )
            .write_dynamic(0x2000, &entries)
            .write_rel32(0x2100, &[(0x3200, raw_type)])
            .write_bytes(0x2200, &0x1235_u32.to_le_bytes())
            .build();
        let planned = planned_arm32(&bytes);
        let allocation_id = AllocationId::new(220 + raw_type);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));

        {
            let mut transaction = ImageLoadTransaction::new(&mut memory);
            let reserved = ImageLoader::new()
                .reserve(planned, &mut transaction)
                .unwrap();
            let mapped = ImageLoader::new()
                .copy_and_zero(reserved, &mut transaction)
                .unwrap();
            let runtime = mapped
                .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
                .unwrap();
            let error = runtime
                .relocate(&mut transaction, &ArmRelocator)
                .unwrap_err();
            assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        }

        assert_eq!(
            u32::from_le_bytes(memory.bytes[0x2200..0x2204].try_into().unwrap()),
            0x1235
        );
        assert_eq!(memory.releases, [allocation_id]);
    }
}

#[test]
fn reserve_rejects_an_elf32_image_outside_the_target_address_space() {
    let bytes = arm32_rel_image(0);
    let planned = planned_arm32(&bytes);
    let allocation_id = AllocationId::new(21);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0xffff_f000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let error = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
    }
    assert_eq!(memory.releases, [allocation_id]);
}

#[test]
fn arm_relocator_rejects_a_32_bit_relative_result_overflow() {
    let bytes = arm32_rel_image(0xffff_f000);
    let planned = planned_arm32(&bytes);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(22),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = ImageLoader::new()
        .reserve(planned, &mut transaction)
        .unwrap();
    let mapped = ImageLoader::new()
        .copy_and_zero(reserved, &mut transaction)
        .unwrap();
    let runtime = mapped
        .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
        .unwrap();

    let error = runtime
        .relocate(&mut transaction, &ArmRelocator)
        .unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::IntegerOverflow);
}

#[test]
fn arm_relocator_rejects_unaligned_and_read_only_targets() {
    for (target, expected_kind) in [
        (0x3201, LoadErrorKind::InvalidAlignment),
        (0x1000, LoadErrorKind::OutOfBounds),
        (0x3300, LoadErrorKind::OutOfBounds),
    ] {
        let bytes = arm32_rel_image_at(0, target);
        let planned = planned_arm32(&bytes);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            AllocationId::new(230 + target),
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        assert_eq!(
            runtime
                .relocate(&mut transaction, &ArmRelocator)
                .unwrap_err()
                .kind(),
            expected_kind
        );
    }
}

#[derive(Default)]
struct FakeCodeCache {
    ranges: std::vec::Vec<crate::TargetRange>,
    fail: bool,
}

impl CodeCache for FakeCodeCache {
    fn synchronize(&mut self, runtime_range: crate::TargetRange) -> LoadResult<()> {
        if self.fail {
            return Err(LoadError::new(
                LoadStage::Cache,
                LoadErrorKind::Backend,
                ErrorContext::TargetRange {
                    start: runtime_range.start(),
                    len: runtime_range.len(),
                },
            ));
        }
        self.ranges.push(runtime_range);
        Ok(())
    }
}

fn riscv_image_with_relro() -> std::vec::Vec<u8> {
    let entries = rela_dynamic_entries();
    ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0x2000, 0x3000, 0x118, 0x300, PF_R | PF_W, 0x1000)
        .add_program_header(
            PT_DYNAMIC,
            0x2000,
            0x3000,
            (entries.len() * 16) as u64,
            (entries.len() * 16) as u64,
            PF_R | PF_W,
            8,
        )
        .add_program_header(PT_GNU_RELRO, 0, 0x3180, 0, 0x80, PF_R, 1)
        .write_dynamic(0x2000, &entries)
        .write_rela64(0x2100, &[(0x3200, 3, 0x1234)])
        .build()
}

#[test]
fn seal_synchronizes_code_applies_relro_and_commits_the_transaction() {
    let bytes = riscv_image_with_relro();
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(23);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut cache = FakeCodeCache::default();

    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = ImageLoader::new()
        .reserve(planned, &mut transaction)
        .unwrap();
    let mapped = ImageLoader::new()
        .copy_and_zero(reserved, &mut transaction)
        .unwrap();
    let runtime = mapped
        .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
        .unwrap();
    let relocated = runtime
        .relocate(&mut transaction, &Riscv64Relocator)
        .unwrap();
    let sealed = relocated.seal(&mut transaction, &mut cache).unwrap();

    assert_eq!(sealed.entry().get(), 0x8000);
    assert_eq!(sealed.protection(), ProtectionLevel::LogicalOnly);
    assert_eq!(sealed.seal_plan().ranges().len(), 6);
    assert_eq!(
        cache.ranges,
        [crate::TargetRange::new(TargetAddr::new(0x8000), 0x100)]
    );
    assert_eq!(
        sealed.seal_plan().ranges()[3].runtime_range().start().get(),
        0xa180
    );
    assert_eq!(sealed.seal_plan().ranges()[3].runtime_range().len(), 0x80);
    assert_eq!(
        sealed.seal_plan().ranges()[3].permissions(),
        MemoryPermissions::READ
    );
    assert_eq!(
        sealed.seal_plan().ranges()[1].permissions(),
        MemoryPermissions::NONE
    );
    assert_eq!(sealed.seal_plan().ranges()[1].runtime_range().len(), 0x1f00);
    assert_eq!(
        sealed.seal_plan().ranges()[5].permissions(),
        MemoryPermissions::NONE
    );
    assert_eq!(sealed.seal_plan().ranges()[5].runtime_range().len(), 0xd00);
    transaction.commit_for(&sealed).unwrap();

    assert_eq!(memory.protects.len(), 6);
    assert!(memory.releases.is_empty());
}

#[test]
fn seal_merges_adjacent_ranges_with_identical_permissions() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 0, 0x100, PF_R | PF_X, 1)
        .add_program_header(PT_LOAD, 0, 0x1100, 0, 0x100, PF_R | PF_X, 1)
        .build();
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(240),
        TargetAddr::new(0x8000),
        0x200,
        1,
        AllocationOwnership::Owned,
    ));
    let mut cache = FakeCodeCache::default();

    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = ImageLoader::new()
        .reserve(planned, &mut transaction)
        .unwrap();
    let mapped = ImageLoader::new()
        .copy_and_zero(reserved, &mut transaction)
        .unwrap();
    let runtime = mapped
        .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
        .unwrap();
    let relocated = runtime
        .relocate(&mut transaction, &Riscv64Relocator)
        .unwrap();
    let sealed = relocated.seal(&mut transaction, &mut cache).unwrap();

    assert_eq!(sealed.seal_plan().ranges().len(), 1);
    assert_eq!(sealed.seal_plan().ranges()[0].runtime_range().len(), 0x200);
    assert_eq!(
        cache.ranges,
        [sealed.seal_plan().ranges()[0].runtime_range()]
    );
    transaction.commit_for(&sealed).unwrap();
}

#[test]
fn cache_failure_prevents_protection_and_rolls_back() {
    let bytes = riscv_image_with_relro();
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(24);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut cache = FakeCodeCache {
        ranges: std::vec::Vec::new(),
        fail: true,
    };

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap();
        let mapped = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap();
        let runtime = mapped
            .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
            .unwrap();
        let relocated = runtime
            .relocate(&mut transaction, &Riscv64Relocator)
            .unwrap();
        let error = relocated.seal(&mut transaction, &mut cache).unwrap_err();
        assert_eq!(error.stage(), LoadStage::Cache);
    }

    assert!(memory.protects.is_empty());
    assert_eq!(memory.releases, [allocation_id]);
}

#[test]
fn protection_failure_rolls_back_the_owned_allocation() {
    let bytes = riscv_image_with_relro();
    for failure_call in 0..6 {
        let planned = planned_image(&bytes, ExpectedElfType::Dyn);
        let allocation_id = AllocationId::new(250 + failure_call as u32);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        memory.fail_protect_at = Some(failure_call);
        let mut cache = FakeCodeCache::default();

        {
            let mut transaction = ImageLoadTransaction::new(&mut memory);
            let reserved = ImageLoader::new()
                .reserve(planned, &mut transaction)
                .unwrap();
            let mapped = ImageLoader::new()
                .copy_and_zero(reserved, &mut transaction)
                .unwrap();
            let runtime = mapped
                .decode_runtime(&mut transaction, RuntimeFeaturePolicy::Phase0)
                .unwrap();
            let relocated = runtime
                .relocate(&mut transaction, &Riscv64Relocator)
                .unwrap();
            assert!(relocated.seal(&mut transaction, &mut cache).is_err());
        }

        assert_eq!(memory.protects.len(), failure_call);
        assert_eq!(memory.releases, [allocation_id]);
    }
}

#[test]
fn runtime_reads_and_relocation_write_failures_roll_back() {
    let bytes = riscv_image_with_relro();

    for failure_call in 0..5 {
        let allocation_id = AllocationId::new(270 + failure_call as u32);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        memory.fail_read_at = Some(failure_call);
        let mut cache = FakeCodeCache::default();
        assert!(crate::load_image(
            SliceElfReader::new(&bytes),
            riscv64_request(),
            &mut memory,
            &mut cache,
            RuntimeFeaturePolicy::Phase0,
            &Riscv64Relocator,
        )
        .is_err());
        assert_eq!(memory.reads.borrow().len(), failure_call);
        assert_eq!(memory.releases, [allocation_id]);
    }

    let allocation_id = AllocationId::new(275);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    // The two segment-copy writes succeed; the relocation write fails.
    memory.fail_write_at = Some(2);
    let mut cache = FakeCodeCache::default();
    assert!(crate::load_image(
        SliceElfReader::new(&bytes),
        riscv64_request(),
        &mut memory,
        &mut cache,
        RuntimeFeaturePolicy::Phase0,
        &Riscv64Relocator,
    )
    .is_err());
    assert_eq!(memory.writes.len(), 2);
    assert_eq!(memory.releases, [allocation_id]);
}

#[test]
fn load_image_orchestrates_and_commits_the_phase0_pipeline() {
    let bytes = riscv_image_with_relro();
    let request = riscv64_request();
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(26),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut cache = FakeCodeCache::default();

    let sealed = crate::load_image(
        SliceElfReader::new(&bytes),
        request,
        &mut memory,
        &mut cache,
        RuntimeFeaturePolicy::Phase0,
        &Riscv64Relocator,
    )
    .unwrap();

    assert_eq!(sealed.entry().get(), 0x8000);
    assert_eq!(sealed.metadata().relocations().len(), 1);
    assert!(memory.releases.is_empty());
}

#[test]
fn load_image_rolls_back_when_the_phase0_policy_rejects_a_dependency() {
    let entries = [(DT_NEEDED, 1), (DT_NULL, 0)];
    let bytes = image_with_dynamic_entries(&entries, 3);
    let allocation_id = AllocationId::new(27);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut cache = FakeCodeCache::default();

    let error = crate::load_image(
        SliceElfReader::new(&bytes),
        riscv64_request(),
        &mut memory,
        &mut cache,
        RuntimeFeaturePolicy::Phase0,
        &Riscv64Relocator,
    )
    .unwrap_err();

    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
    assert_eq!(memory.releases, [allocation_id]);
}
