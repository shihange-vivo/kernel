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
        DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DF_TEXTREL, DT_DEBUG, DT_FLAGS, DT_FLAGS_1, DT_JMPREL,
        DT_NEEDED, DT_NULL, DT_PLTREL, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT, DT_RELSZ,
        DT_TEXTREL,
    },
    header::{
        EI_ABIVERSION, EI_CLASS, EI_DATA, ELFCLASS32, ELFDATA2MSB, EM_ARM, EM_RISCV, ET_DYN,
        ET_EXEC,
    },
    reloc::{R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_RELATIVE},
    Elf,
};

use self::fixture::ElfFixtureBuilder;
use crate::{
    AllocationId, AllocationLease, AllocationOwnership, AllocationRequest, ArmRelocator,
    ArtifactProfile, ArtifactRequest, CodeCache, ElfClass, ElfReader, Endian, EntryMode,
    ErrorContext, ExpectedElfType, HeaderFlagsPolicy, ImageAllocation, ImageCommitMemory,
    ImageLoadTransaction, ImageLoader, ImageMemory, ImageProtectionMemory, LoadError,
    LoadErrorKind, LoadLimits, LoadResult, LoadStage, MemoryError, MemoryPermissions, MemoryResult,
    MutationProgress, Phase0ArtifactPolicy, Placement, PlannedArtifact, ProtectionCapabilities,
    ProtectionLevel, RelocationAddend, Riscv64Relocator, SealedState, SliceElfReader,
    SourceSnapshot, TargetAddr, TargetLocation,
};
use goblin::elf::program_header::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_TLS,
};

fn test_profile(class: ElfClass, machine: u16) -> ArtifactProfile {
    ArtifactProfile::new(
        class,
        Endian::Little,
        machine,
        HeaderFlagsPolicy::exact(0),
        EntryMode::direct(1, 1),
        1,
        crate::RelativeValuePolicy::SAME_IMAGE,
    )
}

fn test_riscv64_profile() -> ArtifactProfile {
    test_profile(ElfClass::Elf64, EM_RISCV)
}

fn riscv64_request() -> ArtifactRequest {
    ArtifactRequest::new(
        ExpectedElfType::Dyn,
        test_riscv64_profile(),
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
fn compatibility_loader_rejects_invalid_magic() {
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
fn range_errors_are_stage_neutral_until_consumed() {
    let range_error = TargetAddr::new(u64::MAX).checked_add(1).unwrap_err();
    assert_eq!(range_error.kind(), LoadErrorKind::IntegerOverflow);

    let byte_error = crate::identity::read_u64(&[0; 7], 0, Endian::Little).unwrap_err();
    assert_eq!(byte_error.kind(), LoadErrorKind::OutOfBounds);
    let memory_error = fake_access_error(TargetLocation::new(AllocationId::new(1), 2), 4);
    assert_eq!(memory_error.kind(), LoadErrorKind::Backend);

    for stage in [
        LoadStage::Parse,
        LoadStage::Plan,
        LoadStage::Map,
        LoadStage::Metadata,
        LoadStage::Relocate,
        LoadStage::Cache,
        LoadStage::Seal,
        LoadStage::Publish,
    ] {
        assert_eq!(range_error.at(stage).stage(), stage);
        assert_eq!(byte_error.at(stage).stage(), stage);
        assert_eq!(memory_error.at(stage).stage(), stage);
    }
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
    fn snapshot(&self) -> LoadResult<SourceSnapshot> {
        self.inner.snapshot()
    }

    fn len(&self) -> LoadResult<u64> {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let call = self.log.calls.get();
        self.log.calls.set(call + 1);
        self.log.reads.borrow_mut().push((offset, dst.len()));
        if let Some((_, failure)) = self.failure.filter(|(index, _)| *index == call) {
            return Err(LoadError::new(
                LoadStage::Publish,
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
            assert_eq!(error.stage(), LoadStage::Read);
            assert_eq!(error.kind(), expected_kind);
            assert_eq!(log.calls.get(), failure_call + 1);
            assert_eq!(log.reads.borrow().len(), failure_call + 1);
        }
    }

    let (reader, log) = RecordingReader::new(&bytes, None);
    ImageLoader::new().admit(reader, riscv64_request()).unwrap();
    assert_eq!(log.reads.borrow().as_slice(), [(0, 16), (0, 64)]);
}

#[derive(Debug)]
struct VersionedReader<'a> {
    inner: SliceElfReader<'a>,
    version: Rc<Cell<u64>>,
}

impl ElfReader for VersionedReader<'_> {
    fn snapshot(&self) -> LoadResult<SourceSnapshot> {
        Ok(SourceSnapshot::new(self.version.get()))
    }

    fn len(&self) -> LoadResult<u64> {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        self.inner.read_exact_at(offset, dst)
    }
}

#[test]
fn source_version_change_is_rejected_before_allocation() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let version = Rc::new(Cell::new(7));
    let reader = VersionedReader {
        inner: SliceElfReader::new(&bytes),
        version: Rc::clone(&version),
    };
    let loader = ImageLoader::new();
    let admitted = loader.admit(reader, riscv64_request()).unwrap();
    version.set(8);

    let error = loader.plan(admitted).unwrap_err();
    assert_eq!(error.stage(), LoadStage::Parse);
    assert_eq!(error.kind(), LoadErrorKind::SourceChanged);
}

#[test]
fn source_version_change_before_copy_aborts_without_modifying_the_target() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let version = Rc::new(Cell::new(1));
    let reader = VersionedReader {
        inner: SliceElfReader::new(&bytes),
        version: Rc::clone(&version),
    };
    let loader = ImageLoader::new();
    let admitted = loader.admit(reader, riscv64_request()).unwrap();
    let planned = loader.plan(admitted).unwrap();
    version.set(2);
    let allocation_id = AllocationId::new(308);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x1000,
        0x1000,
        AllocationOwnership::Owned,
    ));

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = loader.reserve(planned, &mut transaction).unwrap();
        let error = loader
            .copy_and_zero(reserved, &mut transaction)
            .unwrap_err();
        assert_eq!(error.stage(), LoadStage::Map);
        assert_eq!(error.kind(), LoadErrorKind::SourceChanged);
    }

    assert!(memory.writes.is_empty());
    assert!(memory.zeros.is_empty());
    assert_eq!(memory.releases, [allocation_id]);
    assert_eq!(memory.abort_progress, [MutationProgress::Reserved]);
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
        test_profile(ElfClass::Elf32, EM_ARM),
        LoadLimits::default(),
    );
    let admitted = ImageLoader::new()
        .admit(SliceElfReader::new(&arm), request)
        .unwrap();
    assert_eq!(admitted.header().class(), ElfClass::Elf32);
    assert_eq!(admitted.file_len(), arm.len() as u64);
}

#[test]
fn admit_enforces_profile_header_flags_and_entry_mode() {
    const EF_ARM_EABI_VER5: u32 = 0x0500_0000;
    const EF_ARM_ABI_FLOAT_SOFT: u32 = 0x0000_0200;
    const EF_ARM_ABI_FLOAT_HARD: u32 = 0x0000_0400;

    let arm_request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::arm_thumb_v7m_soft(),
        LoadLimits::default(),
    );
    let valid_arm = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN)
        .set_flags(EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_SOFT)
        .set_entry(0x1001)
        .build();
    ImageLoader::new()
        .admit(SliceElfReader::new(&valid_arm), arm_request)
        .unwrap();

    for (flags, entry) in [
        (0, 0x1001),
        (EF_ARM_EABI_VER5, 0x1001),
        (EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_HARD, 0x1001),
        (EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_SOFT, 0x1000),
    ] {
        let bytes = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN)
            .set_flags(flags)
            .set_entry(entry)
            .build();
        assert_eq!(
            ImageLoader::new()
                .admit(SliceElfReader::new(&bytes), arm_request)
                .unwrap_err()
                .kind(),
            LoadErrorKind::UnsupportedByProfile
        );
    }

    let riscv_request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::riscv_soft(ElfClass::Elf64),
        LoadLimits::default(),
    );
    for (flags, entry) in [(1, 0x1000), (0, 0x1002)] {
        let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_flags(flags)
            .set_entry(entry)
            .build();
        assert_eq!(
            ImageLoader::new()
                .admit(SliceElfReader::new(&bytes), riscv_request)
                .unwrap_err()
                .kind(),
            LoadErrorKind::UnsupportedByProfile
        );
    }

    let compressed_riscv_request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf64),
        LoadLimits::default(),
    );
    let compressed = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_flags(1)
        .set_entry(0x1002)
        .build();
    ImageLoader::new()
        .admit(SliceElfReader::new(&compressed), compressed_riscv_request)
        .unwrap();

    for (flags, entry) in [(0, 0x1002), (3, 0x1002), (1, 0x1001)] {
        let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_flags(flags)
            .set_entry(entry)
            .build();
        assert_eq!(
            ImageLoader::new()
                .admit(SliceElfReader::new(&bytes), compressed_riscv_request)
                .unwrap_err()
                .kind(),
            LoadErrorKind::UnsupportedByProfile
        );
    }
}

#[test]
fn generic_artifact_profile_rejects_architecture_flags_by_default() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_flags(1)
        .build();

    assert_eq!(
        ImageLoader::new()
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap_err()
            .kind(),
        LoadErrorKind::UnsupportedByProfile
    );
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

    let wrong_abi_version = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_ident(EI_ABIVERSION, 1)
        .build();
    let error = ImageLoader::new()
        .admit(SliceElfReader::new(&wrong_abi_version), riscv64_request())
        .unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
    assert_eq!(
        error.context(),
        &ErrorContext::HeaderField {
            field: crate::HeaderField::AbiVersion,
            value: 1,
        }
    );

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
        test_riscv64_profile(),
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
        test_riscv64_profile(),
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
    assert_eq!(parsed.dynamic().unwrap().index(), 1);
    assert_eq!(parsed.relro().unwrap().start().get(), 0x2080);
    assert_eq!(parsed.stack_policy(), crate::StackPolicy::NonExecutable);
}

#[test]
fn plan_rejects_dynamic_segments_outside_a_matching_readable_load_segment() {
    for (file_offset, vaddr, permissions, expected_field, expected_value) in [
        (
            0x280,
            0x3000,
            PF_R | PF_W,
            crate::ProgramHeaderField::FileRange,
            0x280,
        ),
        (
            0x200,
            0x4000,
            PF_R | PF_W,
            crate::ProgramHeaderField::VirtualRange,
            0x4000,
        ),
        (
            0x200,
            0x3000,
            PF_W,
            crate::ProgramHeaderField::VirtualRange,
            0x3000,
        ),
    ] {
        let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .set_entry(0x1000)
            .add_program_header(PT_LOAD, 0x100, 0x1000, 0x100, 0x100, PF_R | PF_X, 0x100)
            .add_program_header(PT_LOAD, 0x200, 0x3000, 0x100, 0x100, permissions, 0x100)
            .add_program_header(PT_DYNAMIC, file_offset, vaddr, 16, 16, PF_R | PF_W, 8)
            .build();
        let loader = ImageLoader::new();
        let admitted = loader
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap();
        let error = loader.plan(admitted).unwrap_err();
        assert_eq!(error.stage(), LoadStage::Plan);
        assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
        assert_eq!(
            error.context(),
            &ErrorContext::ProgramHeader {
                index: 2,
                field: expected_field,
                value: expected_value,
            }
        );
    }
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
fn parser_records_program_features_before_phase0_policy_rejects_them() {
    for program_type in [PT_INTERP, PT_TLS] {
        let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
            .add_program_header(program_type, 0, 0, 0, 0, PF_R, 1)
            .build();
        let loader = ImageLoader::new();
        let admitted = loader
            .admit(SliceElfReader::new(&bytes), riscv64_request())
            .unwrap();
        let parsed = loader.inspect(&admitted).unwrap();
        match program_type {
            PT_INTERP => assert!(parsed.program_features().interpreter().is_some()),
            PT_TLS => assert!(parsed.program_features().tls().is_some()),
            _ => unreachable!(),
        }
        assert_eq!(
            loader.plan(admitted).unwrap_err().kind(),
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
    let parsed = loader.inspect(&admitted).unwrap();
    assert!(parsed.program_features().has_executable_stack());
    assert_eq!(
        loader.plan(admitted).unwrap_err().kind(),
        LoadErrorKind::UnsupportedByProfile
    );
}

#[derive(Clone, Copy)]
struct AcceptAllFeatures;

impl crate::ArtifactFeaturePolicy for AcceptAllFeatures {
    fn validate_program_features(
        &self,
        _features: &crate::ProgramFeatureSummary,
    ) -> LoadResult<()> {
        Ok(())
    }

    fn validate_dynamic_features(
        &self,
        _features: &crate::DynamicFeatureSummary,
    ) -> LoadResult<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct WrongStagePolicy {
    reject_program: bool,
}

impl crate::ArtifactFeaturePolicy for WrongStagePolicy {
    fn validate_program_features(
        &self,
        _features: &crate::ProgramFeatureSummary,
    ) -> LoadResult<()> {
        if self.reject_program {
            Err(LoadError::new(
                LoadStage::Publish,
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            ))
        } else {
            Ok(())
        }
    }

    fn validate_dynamic_features(
        &self,
        _features: &crate::DynamicFeatureSummary,
    ) -> LoadResult<()> {
        if self.reject_program {
            Ok(())
        } else {
            Err(LoadError::new(
                LoadStage::Publish,
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            ))
        }
    }
}

#[test]
fn feature_policy_errors_are_attributed_to_the_consuming_stage() {
    let program = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&program), riscv64_request())
        .unwrap();
    let error = loader
        .plan_with_policy(
            admitted,
            &WrongStagePolicy {
                reject_program: true,
            },
        )
        .unwrap_err();
    assert_eq!(error.stage(), LoadStage::Plan);

    let dynamic = image_with_dynamic_entries(&[(DT_FLAGS_1, DF_1_PIE), (DT_NULL, 0)], 0);
    let admitted = loader
        .admit(SliceElfReader::new(&dynamic), riscv64_request())
        .unwrap();
    let planned = loader
        .plan_with_policy(admitted, &AcceptAllFeatures)
        .unwrap();
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(390),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let reserved = loader.reserve(planned, &mut transaction).unwrap();
        let mapped = loader.copy_and_zero(reserved, &mut transaction).unwrap();
        let error = mapped
            .decode_runtime(
                &mut transaction,
                &WrongStagePolicy {
                    reject_program: false,
                },
            )
            .unwrap_err();
        assert_eq!(error.stage(), LoadStage::Metadata);
    }
    assert_eq!(memory.releases, [AllocationId::new(390)]);
}

#[test]
fn alternate_policy_reuses_the_structural_program_and_dynamic_parsers() {
    let program = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_INTERP, 0, 0, 0, 0, PF_R, 1)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(SliceElfReader::new(&program), riscv64_request())
        .unwrap();
    loader
        .plan_with_policy(admitted, &AcceptAllFeatures)
        .unwrap();

    let entries = [(DT_NEEDED, 7), (DT_NULL, 0)];
    let dynamic = image_with_dynamic_entries(&entries, 3);
    let planned = planned_image(&dynamic, ExpectedElfType::Dyn);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(309),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = loader.reserve(planned, &mut transaction).unwrap();
    let mapped = loader.copy_and_zero(reserved, &mut transaction).unwrap();
    let runtime = mapped
        .decode_runtime(&mut transaction, &AcceptAllFeatures)
        .unwrap();
    assert_eq!(
        runtime.metadata().features().first_extended_tag(),
        Some((DT_NEEDED, 7))
    );
    transaction.disarm_for_test();
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
        .set_flags(0x0500_0200)
        .set_entry(0x1001)
        .add_program_header(PT_LOAD, 0, 0x1000, 52, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::arm_thumb_v7m_soft(),
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
    let error = loader.plan(admitted).unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::IntegerOverflow);
    assert_eq!(error.stage(), LoadStage::Parse);

    let alignment_overflow = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 0, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0, u64::MAX - 0x7ff, 0, 0x100, PF_R | PF_W, 1)
        .build();
    let admitted = loader
        .admit(SliceElfReader::new(&alignment_overflow), riscv64_request())
        .unwrap();
    let error = loader.plan(admitted).unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::IntegerOverflow);
    assert_eq!(error.stage(), LoadStage::Plan);
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

    let truncated_entry = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 0, 2, PF_R | PF_X, 1)
        .build();
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        ArtifactProfile::riscv_soft(ElfClass::Elf64),
        LoadLimits::default(),
    );
    let admitted = loader
        .admit(SliceElfReader::new(&truncated_entry), request)
        .unwrap();
    let error = loader.plan(admitted).unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::PermissionConflict);
    assert_eq!(
        error.context(),
        &ErrorContext::TargetRange {
            start: TargetAddr::new(0x1000),
            len: 4,
        }
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
        LoadLimits::new(1024, 16).with_layout_limits(0x800, u64::MAX),
        LoadLimits::new(1024, 16).with_layout_limits(u64::MAX, 0),
    ] {
        let request = ArtifactRequest::new(ExpectedElfType::Dyn, test_riscv64_profile(), limits);
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
    fail_prepare_install: bool,
    protection_granule: u64,
    max_protection_ranges: usize,
    fail_alias_preflight: bool,
    fixed_poisoned: bool,
    requests: std::vec::Vec<AllocationRequest>,
    releases: std::vec::Vec<AllocationId>,
    committed_releases: std::vec::Vec<AllocationId>,
    abort_progress: std::vec::Vec<MutationProgress>,
    installed_lease: Option<AllocationLease>,
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
            fail_prepare_install: false,
            protection_granule: 1,
            max_protection_ranges: usize::MAX,
            fail_alias_preflight: false,
            fixed_poisoned: false,
            requests: std::vec::Vec::new(),
            releases: std::vec::Vec::new(),
            committed_releases: std::vec::Vec::new(),
            abort_progress: std::vec::Vec::new(),
            installed_lease: None,
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
            fail_prepare_install: false,
            protection_granule: 1,
            max_protection_ranges: usize::MAX,
            fail_alias_preflight: false,
            fixed_poisoned: false,
            requests: std::vec::Vec::new(),
            releases: std::vec::Vec::new(),
            committed_releases: std::vec::Vec::new(),
            abort_progress: std::vec::Vec::new(),
            installed_lease: None,
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

    fn release_installed(&mut self) {
        if let Some(lease) = self.installed_lease.take() {
            self.release_committed(lease);
        }
    }
}

impl ImageMemory for FakeMemory {
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<AllocationLease> {
        self.requests.push(*request);
        if self.fail_allocate {
            return Err(LoadError::new(
                LoadStage::Allocate,
                LoadErrorKind::OutOfMemory,
                ErrorContext::None,
            ));
        }
        // SAFETY: FakeMemory returns one fresh lease for its configured test
        // allocation and the transaction consumes it exactly once.
        Ok(unsafe {
            AllocationLease::from_allocation(
                self.allocation.expect("test allocation must be configured"),
            )
        })
    }

    fn abort_image(&mut self, lease: AllocationLease, progress: MutationProgress) {
        if lease.allocation().ownership() == AllocationOwnership::BorrowedFixed
            && progress >= MutationProgress::BytesModified
        {
            self.fixed_poisoned = true;
        }
        self.releases.push(lease.allocation().id());
        self.abort_progress.push(progress);
    }

    fn release_committed(&mut self, lease: AllocationLease) {
        self.committed_releases.push(lease.allocation().id());
    }

    fn validate_access(
        &self,
        location: TargetLocation,
        len: u64,
        _permissions: MemoryPermissions,
    ) -> MemoryResult<()> {
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

    fn write(&mut self, location: TargetLocation, data: &[u8]) -> MemoryResult<()> {
        self.validate_access(location, data.len() as u64, MemoryPermissions::WRITE)?;
        if self.fail_write_at == Some(self.writes.len()) {
            return Err(fake_access_error(location, data.len() as u64));
        }
        let start = location.offset() as usize;
        self.bytes[start..start + data.len()].copy_from_slice(data);
        self.writes.push((location, data.len()));
        Ok(())
    }

    fn zero(&mut self, location: TargetLocation, len: u64) -> MemoryResult<()> {
        self.validate_access(location, len, MemoryPermissions::WRITE)?;
        if self.fail_zero_at == Some(self.zeros.len()) {
            return Err(fake_access_error(location, len));
        }
        let start = location.offset() as usize;
        self.bytes[start..start + len as usize].fill(0);
        self.zeros.push((location, len));
        Ok(())
    }

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> MemoryResult<()> {
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
    ) -> MemoryResult<ProtectionLevel> {
        self.validate_access(location, len, permissions)?;
        if self.fail_protect_at == Some(self.protects.len()) {
            return Err(fake_access_error(location, len));
        }
        self.protects.push((location, len, permissions));
        Ok(ProtectionLevel::LogicalOnly)
    }
}

#[derive(Debug)]
struct FakePreparedInstall {
    allocation: ImageAllocation,
    entry: TargetAddr,
    relocation_count: usize,
}

#[derive(Debug)]
struct FakeCommitReceipt {
    entry: TargetAddr,
    relocation_count: usize,
}

impl ImageCommitMemory for FakeMemory {
    type PreparedInstall = FakePreparedInstall;
    type CommitReceipt = FakeCommitReceipt;

    fn prepare_install(
        &mut self,
        allocation: &ImageAllocation,
        sealed: &SealedState,
    ) -> LoadResult<Self::PreparedInstall> {
        if self.fail_prepare_install
            || self.allocation != Some(*allocation)
            || sealed.allocation() != allocation
        {
            return Err(LoadError::new(
                LoadStage::Publish,
                LoadErrorKind::Backend,
                ErrorContext::Allocation {
                    base: allocation.target_base(),
                    len: allocation.len(),
                    align: allocation.align(),
                },
            ));
        }
        Ok(FakePreparedInstall {
            allocation: *allocation,
            entry: sealed.entry(),
            relocation_count: sealed.metadata().relocations().len(),
        })
    }

    unsafe fn commit_install(
        &mut self,
        prepared: Self::PreparedInstall,
        _sealed: SealedState,
        lease: AllocationLease,
    ) -> Self::CommitReceipt {
        self.allocation = Some(prepared.allocation);
        self.installed_lease = Some(lease);
        FakeCommitReceipt {
            entry: prepared.entry,
            relocation_count: prepared.relocation_count,
        }
    }
}

impl ImageProtectionMemory for FakeMemory {
    fn protection_capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities::new(self.protection_granule, self.max_protection_ranges)
    }

    fn validate_protection_aliases(
        &self,
        allocation: &ImageAllocation,
        _prepared: &crate::PreparedProtectionPlan,
    ) -> LoadResult<()> {
        if self.fail_alias_preflight {
            Err(LoadError::new(
                LoadStage::Seal,
                LoadErrorKind::PermissionConflict,
                ErrorContext::Allocation {
                    base: allocation.target_base(),
                    len: allocation.len(),
                    align: allocation.align(),
                },
            ))
        } else {
            Ok(())
        }
    }
}

fn fake_access_error(location: TargetLocation, len: u64) -> MemoryError {
    MemoryError::new(
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
        test_riscv64_profile(),
        LoadLimits::default(),
    );
    planned_image_with_request(bytes, request)
}

fn planned_image_with_request(
    bytes: &[u8],
    request: ArtifactRequest,
) -> PlannedArtifact<SliceElfReader<'_>> {
    let loader = ImageLoader::new();
    let admitted = loader.admit(SliceElfReader::new(bytes), request).unwrap();
    loader.plan(admitted).unwrap()
}

fn reserved_stage<'m, 'r>(
    bytes: &'r [u8],
    memory: &'m mut FakeMemory,
) -> crate::ReservedImage<'m, FakeMemory, SliceElfReader<'r>> {
    ImageLoader::new()
        .reserve_staged(planned_image(bytes, ExpectedElfType::Dyn), memory)
        .unwrap()
}

fn mapped_stage<'m>(
    bytes: &[u8],
    memory: &'m mut FakeMemory,
) -> crate::MappedImage<'m, FakeMemory> {
    reserved_stage(bytes, memory).copy_and_zero().unwrap()
}

fn runtime_stage<'m>(
    bytes: &[u8],
    memory: &'m mut FakeMemory,
) -> crate::RuntimeImage<'m, FakeMemory> {
    mapped_stage(bytes, memory)
        .decode_runtime(&Phase0ArtifactPolicy)
        .unwrap()
}

fn relocated_stage<'m>(
    bytes: &[u8],
    memory: &'m mut FakeMemory,
) -> crate::RelocatedImage<'m, FakeMemory> {
    runtime_stage(bytes, memory)
        .relocate(&Riscv64Relocator)
        .unwrap()
}

fn prepared_stage<'m>(
    bytes: &[u8],
    memory: &'m mut FakeMemory,
    cache: &mut FakeCodeCache,
) -> crate::PreparedImage<'m, FakeMemory> {
    relocated_stage(bytes, memory).seal(cache).unwrap()
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
            AllocationId::new(95),
            TargetAddr::new(0x8000),
            0x2000,
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

    let lease = ImageMemory::allocate_image(&mut mapper, &request).unwrap();
    let allocation = *lease.allocation();
    assert_eq!(allocation.ownership(), AllocationOwnership::Owned);
    assert_eq!(allocation.target_base().get() % 0x1000, 0);
    assert_eq!(allocation.len(), 0x2000);

    ImageMemory::abort_image(&mut mapper, lease, MutationProgress::Reserved);
    assert!(mapper.real_start().is_err());
}

#[test]
fn memory_mapper_poison_blocks_fixed_reuse_until_platform_reset() {
    let buffer = std::boxed::Box::leak(std::vec![0u8; 0x1000].into_boxed_slice());
    let start = buffer.as_mut_ptr() as usize;
    let regions = std::boxed::Box::leak(std::boxed::Box::new([unsafe {
        crate::MemoryRegion::new(
            start,
            start + buffer.len(),
            MemoryPermissions::READ.union(MemoryPermissions::WRITE),
        )
    }]));
    let request = AllocationRequest::new(
        Placement::Fixed(crate::TargetRange::new(
            TargetAddr::new(start as u64),
            buffer.len() as u64,
        )),
        buffer.len() as u64,
        1,
    );
    let mut mapper = crate::MemoryMapper::new(Some(regions));

    let lease = ImageMemory::allocate_image(&mut mapper, &request).unwrap();
    ImageMemory::abort_image(&mut mapper, lease, MutationProgress::BytesModified);
    assert!(mapper.is_fixed_poisoned());
    assert_eq!(
        ImageMemory::allocate_image(&mut mapper, &request)
            .unwrap_err()
            .kind(),
        LoadErrorKind::Backend
    );

    // SAFETY: this test has exclusive access to the backing buffer and no
    // entry point was published. Filling it restores the complete range.
    buffer.fill(0);
    unsafe { mapper.reset_fixed_poison() };
    let lease = ImageMemory::allocate_image(&mut mapper, &request).unwrap();
    ImageMemory::abort_image(&mut mapper, lease, MutationProgress::Reserved);
    assert!(!mapper.is_fixed_poisoned());
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

#[derive(Debug)]
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
    fn snapshot(&self) -> LoadResult<SourceSnapshot> {
        self.inner.snapshot()
    }

    fn len(&self) -> LoadResult<u64> {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        if offset >= self.fail_at {
            return Err(LoadError::new(
                LoadStage::Publish,
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
fn program_header_read_failure_is_attributed_to_parse() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0, 0x1000, 64, 0x100, PF_R | PF_X, 0x1000)
        .build();
    let loader = ImageLoader::new();
    let admitted = loader
        .admit(FaultingReader::new(&bytes, 64), riscv64_request())
        .unwrap();

    let error = loader.plan(admitted).unwrap_err();
    assert_eq!(error.stage(), LoadStage::Parse);
    assert_eq!(error.kind(), LoadErrorKind::Io);
}

#[test]
fn copy_failure_rolls_back_the_owned_allocation() {
    let (bytes, _) = image_with_bss_and_gap(ET_DYN);
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        test_riscv64_profile(),
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
        assert_eq!(error.stage(), LoadStage::Map);
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
            assert_eq!(error.stage(), LoadStage::Map);
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
        let error = ImageLoader::new()
            .copy_and_zero(reserved, &mut transaction)
            .unwrap_err();
        assert_eq!(error.stage(), LoadStage::Map);
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
            let error = ImageLoader::new()
                .copy_and_zero(reserved, &mut transaction)
                .unwrap_err();
            assert_eq!(error.stage(), LoadStage::Map);
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
        let request = ArtifactRequest::new(ExpectedElfType::Dyn, test_riscv64_profile(), limits);
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
        .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
        .unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
}

fn decode_runtime_for_test(entries: &[(u64, u64)], limits: LoadLimits) -> LoadResult<usize> {
    let bytes = image_with_dynamic_entries(entries, 3);
    let request = ArtifactRequest::new(ExpectedElfType::Dyn, test_riscv64_profile(), limits);
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
    let runtime = mapped.decode_runtime(&mut transaction, &Phase0ArtifactPolicy)?;
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
    assert_eq!(
        decode_runtime_for_test(
            &rela_dynamic_entries(),
            LoadLimits::default().with_runtime_memory_limits(0, u64::MAX),
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
        (DT_FLAGS, 1 << 63),
        (DT_FLAGS_1, 1 << 63),
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
fn phase0_policy_accepts_only_the_explicit_dynamic_flag_baseline() {
    for entries in [
        [(DT_FLAGS, DF_BIND_NOW), (DT_NULL, 0)],
        [(DT_FLAGS_1, DF_1_NOW | DF_1_PIE), (DT_NULL, 0)],
    ] {
        assert_eq!(
            decode_runtime_for_test(&entries, LoadLimits::default()).unwrap(),
            0
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
        .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
    let bytes = image_with_dynamic_relocation(&rela_dynamic_entries(), 0x3200, 3, 0x1020);
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
        0x8020
    );
    assert!(memory.releases.is_empty());
}

#[test]
fn riscv64_relocator_rejects_out_of_image_values_and_duplicate_targets_before_writing() {
    let duplicate_entries = [
        (DT_RELA, 0x3100),
        (DT_RELASZ, 48),
        (DT_RELAENT, 24),
        (DT_NULL, 0),
    ];
    let duplicate = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .set_entry(0x1000)
        .add_program_header(PT_LOAD, 0x1000, 0x1000, 0x100, 0x100, PF_R | PF_X, 0x1000)
        .add_program_header(PT_LOAD, 0x2000, 0x3000, 0x130, 0x300, PF_R | PF_W, 0x1000)
        .add_program_header(
            PT_DYNAMIC,
            0x2000,
            0x3000,
            (duplicate_entries.len() * 16) as u64,
            (duplicate_entries.len() * 16) as u64,
            PF_R | PF_W,
            8,
        )
        .write_dynamic(0x2000, &duplicate_entries)
        .write_rela64(0x2100, &[(0x3200, 3, 0x1020), (0x3200, 3, 0x1030)])
        .build();
    let outside = image_with_dynamic_entries(&rela_dynamic_entries(), 3);

    for (index, (bytes, expected_kind)) in [
        (outside, LoadErrorKind::OutOfBounds),
        (duplicate, LoadErrorKind::BadElf),
    ]
    .into_iter()
    .enumerate()
    {
        let planned = planned_image(&bytes, ExpectedElfType::Dyn);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            AllocationId::new(300 + index as u32),
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
            .unwrap();
        assert_eq!(
            runtime
                .relocate(&mut transaction, &Riscv64Relocator)
                .unwrap_err()
                .kind(),
            expected_kind
        );
        transaction.disarm_for_test();
        assert_eq!(memory.writes.len(), 2);
    }
}

#[test]
fn relocation_operation_byte_budget_is_checked_before_planning_writes() {
    let bytes = image_with_dynamic_relocation(&rela_dynamic_entries(), 0x3200, 3, 0x1020);
    let request = ArtifactRequest::new(
        ExpectedElfType::Dyn,
        test_riscv64_profile(),
        LoadLimits::default().with_runtime_memory_limits(u64::MAX, 0),
    );
    let loader = ImageLoader::new();
    let admitted = loader.admit(SliceElfReader::new(&bytes), request).unwrap();
    let planned = loader.plan(admitted).unwrap();
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        AllocationId::new(302),
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut transaction = ImageLoadTransaction::new(&mut memory);
    let reserved = loader.reserve(planned, &mut transaction).unwrap();
    let mapped = loader.copy_and_zero(reserved, &mut transaction).unwrap();
    let runtime = mapped
        .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
        .unwrap();

    assert_eq!(
        runtime
            .relocate(&mut transaction, &Riscv64Relocator)
            .unwrap_err()
            .kind(),
        LoadErrorKind::ResourceLimit
    );
    transaction.disarm_for_test();
    assert_eq!(memory.writes.len(), 2);
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
        .set_flags(0x0500_0200)
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
        ArtifactProfile::arm_thumb_v7m_soft(),
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
            .set_flags(0x0500_0200)
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
                .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
        .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
    omit_prepared_ranges: bool,
    misreport_completed_ranges: bool,
    misreport_completed_capability: bool,
    requirements: Option<crate::CacheRequirements>,
    scope: Option<crate::ExecutionScope>,
    maintenance: Option<crate::CacheMaintenance>,
}

impl CodeCache for FakeCodeCache {
    fn requirements(&self) -> crate::CacheRequirements {
        self.requirements
            .unwrap_or(crate::CacheRequirements::CURRENT_EXECUTION_CONTEXT)
    }

    fn prepare(
        &self,
        executable_ranges: &[crate::TargetRange],
    ) -> LoadResult<crate::PreparedCacheSync> {
        let executable_ranges = if self.omit_prepared_ranges {
            &[]
        } else {
            executable_ranges
        };
        crate::PreparedCacheSync::try_new(
            executable_ranges,
            self.scope
                .unwrap_or(crate::ExecutionScope::CurrentExecutionContext),
            self.maintenance
                .unwrap_or(crate::CacheMaintenance::InstructionFence),
        )
    }

    fn synchronize(
        &mut self,
        prepared: crate::PreparedCacheSync,
    ) -> LoadResult<crate::CacheSyncOutcome> {
        if self.fail {
            let runtime_range = prepared
                .executable_ranges()
                .first()
                .copied()
                .unwrap_or(crate::TargetRange::new(TargetAddr::new(0), 0));
            return Err(LoadError::new(
                LoadStage::Cache,
                LoadErrorKind::Backend,
                ErrorContext::TargetRange {
                    start: runtime_range.start(),
                    len: runtime_range.len(),
                },
            ));
        }
        self.ranges.extend_from_slice(prepared.executable_ranges());
        if self.misreport_completed_ranges {
            return Ok(crate::PreparedCacheSync::try_new(
                &[],
                prepared.scope(),
                prepared.maintenance(),
            )?
            .complete());
        }
        if self.misreport_completed_capability {
            return Ok(crate::PreparedCacheSync::try_new(
                prepared.executable_ranges(),
                crate::ExecutionScope::AllExecutionContexts,
                crate::CacheMaintenance::CleanAndInvalidate,
            )?
            .complete());
        }
        Ok(prepared.complete())
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
        .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
        .unwrap();
    let relocated = runtime
        .relocate(&mut transaction, &Riscv64Relocator)
        .unwrap();
    let sealed = relocated.seal(&mut transaction, &mut cache).unwrap();

    assert_eq!(sealed.entry().get(), 0x8000);
    assert_eq!(sealed.protection(), ProtectionLevel::LogicalOnly);
    assert_eq!(sealed.seal_plan().ranges().len(), 6);
    assert_eq!(sealed.protections().ranges().len(), 6);
    for (requested, applied) in sealed
        .seal_plan()
        .ranges()
        .iter()
        .zip(sealed.protections().ranges())
    {
        assert_eq!(applied.location(), requested.location());
        assert_eq!(applied.requested_range(), requested.runtime_range());
        assert_eq!(applied.applied_range(), requested.runtime_range());
        assert_eq!(applied.permissions(), requested.permissions());
        assert_eq!(applied.level(), ProtectionLevel::LogicalOnly);
    }
    assert_eq!(
        sealed.cache_sync().scope(),
        crate::ExecutionScope::CurrentExecutionContext
    );
    assert_eq!(
        sealed.cache_sync().maintenance(),
        crate::CacheMaintenance::InstructionFence
    );
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
    transaction.disarm_for_test();

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
        .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
    transaction.disarm_for_test();
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
        ..FakeCodeCache::default()
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
            .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
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
fn cache_requirements_reject_insufficient_scope_and_wrong_maintenance_before_sync() {
    let bytes = riscv_image_with_relro();
    let requirements = [
        crate::CacheRequirements::exact(
            crate::ExecutionScope::AllExecutionContexts,
            crate::CacheMaintenance::InstructionFence,
        ),
        crate::CacheRequirements::exact(
            crate::ExecutionScope::CurrentExecutionContext,
            crate::CacheMaintenance::CleanAndInvalidate,
        ),
    ];

    for (index, requirements) in requirements.into_iter().enumerate() {
        let request = ArtifactRequest::new(
            ExpectedElfType::Dyn,
            test_riscv64_profile(),
            LoadLimits::default(),
        );
        let planned = planned_image_with_request(&bytes, request);
        let allocation_id = AllocationId::new(310 + index as u32);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        let mut cache = FakeCodeCache {
            requirements: Some(requirements),
            ..FakeCodeCache::default()
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
                .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
                .unwrap();
            let relocated = runtime
                .relocate(&mut transaction, &Riscv64Relocator)
                .unwrap();
            let error = relocated.seal(&mut transaction, &mut cache).unwrap_err();
            assert_eq!(error.stage(), LoadStage::Cache);
            assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        }

        assert!(cache.ranges.is_empty());
        assert!(memory.protects.is_empty());
        assert_eq!(memory.releases, [allocation_id]);
        assert_eq!(memory.abort_progress, [MutationProgress::BytesModified]);
    }
}

#[test]
fn protection_batch_rejects_granule_conflicts_and_region_shortage_before_cache_side_effects() {
    let bytes = riscv_image_with_relro();
    for (index, granule, max_ranges, expected_kind, expected_context) in [
        (
            0,
            0x1000,
            usize::MAX,
            LoadErrorKind::PermissionConflict,
            None,
        ),
        (
            1,
            1,
            5,
            LoadErrorKind::ResourceLimit,
            Some(ErrorContext::Limit {
                resource: crate::LimitKind::ProtectionRangeCount,
                actual: 6,
                maximum: 5,
            }),
        ),
        (
            2,
            0,
            usize::MAX,
            LoadErrorKind::Backend,
            Some(ErrorContext::Allocation {
                base: TargetAddr::new(0x8000),
                len: 0x3000,
                align: 0x1000,
            }),
        ),
    ] {
        let planned = planned_image(&bytes, ExpectedElfType::Dyn);
        let allocation_id = AllocationId::new(305 + index);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        memory.protection_granule = granule;
        memory.max_protection_ranges = max_ranges;
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
                .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
                .unwrap();
            let relocated = runtime
                .relocate(&mut transaction, &Riscv64Relocator)
                .unwrap();
            let error = relocated.seal(&mut transaction, &mut cache).unwrap_err();
            assert_eq!(error.stage(), LoadStage::Seal);
            assert_eq!(error.kind(), expected_kind);
            if let Some(expected_context) = expected_context {
                assert_eq!(*error.context(), expected_context);
            }
        }

        assert!(cache.ranges.is_empty());
        assert!(memory.protects.is_empty());
        assert_eq!(memory.releases, [allocation_id]);
        assert_eq!(memory.abort_progress, [MutationProgress::BytesModified]);
    }
}

#[test]
fn cache_prepare_must_preserve_every_executable_range_before_sync() {
    let bytes = riscv_image_with_relro();
    let allocation_id = AllocationId::new(312);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    let mut cache = FakeCodeCache {
        omit_prepared_ranges: true,
        ..FakeCodeCache::default()
    };

    let error = crate::prepare_image(
        SliceElfReader::new(&bytes),
        riscv64_request(),
        &mut memory,
        &mut cache,
        &Riscv64Relocator,
    )
    .unwrap_err();

    assert_eq!(error.stage(), LoadStage::Cache);
    assert_eq!(error.kind(), LoadErrorKind::Backend);
    assert!(cache.ranges.is_empty());
    assert!(memory.protects.is_empty());
    assert_eq!(memory.releases, [allocation_id]);
    assert_eq!(memory.abort_progress, [MutationProgress::BytesModified]);
}

#[test]
fn cache_completion_must_match_the_validated_prepared_token() {
    let bytes = riscv_image_with_relro();
    for (index, misreport_ranges, misreport_capability) in [(0, true, false), (1, false, true)] {
        let allocation_id = AllocationId::new(313 + index);
        let mut memory = FakeMemory::returning(ImageAllocation::new(
            allocation_id,
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ));
        let mut cache = FakeCodeCache {
            misreport_completed_ranges: misreport_ranges,
            misreport_completed_capability: misreport_capability,
            ..FakeCodeCache::default()
        };

        let error = crate::prepare_image(
            SliceElfReader::new(&bytes),
            riscv64_request(),
            &mut memory,
            &mut cache,
            &Riscv64Relocator,
        )
        .unwrap_err();

        assert_eq!(error.stage(), LoadStage::Cache);
        assert_eq!(error.kind(), LoadErrorKind::Backend);
        assert_eq!(cache.ranges.len(), 1);
        assert!(memory.protects.is_empty());
        assert_eq!(memory.releases, [allocation_id]);
        assert_eq!(memory.abort_progress, [MutationProgress::BytesModified]);
    }
}

#[test]
fn protection_alias_conflict_fails_before_cache_and_protection_side_effects() {
    let bytes = riscv_image_with_relro();
    let allocation_id = AllocationId::new(312);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    memory.fail_alias_preflight = true;
    let mut cache = FakeCodeCache::default();

    let error = crate::prepare_image(
        SliceElfReader::new(&bytes),
        riscv64_request(),
        &mut memory,
        &mut cache,
        &Riscv64Relocator,
    )
    .unwrap_err();

    assert_eq!(error.stage(), LoadStage::Seal);
    assert_eq!(error.kind(), LoadErrorKind::PermissionConflict);
    assert!(cache.ranges.is_empty());
    assert!(memory.protects.is_empty());
    assert_eq!(memory.releases, [allocation_id]);
    assert_eq!(memory.abort_progress, [MutationProgress::BytesModified]);
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
                .decode_runtime(&mut transaction, &Phase0ArtifactPolicy)
                .unwrap();
            let relocated = runtime
                .relocate(&mut transaction, &Riscv64Relocator)
                .unwrap();
            assert!(relocated.seal(&mut transaction, &mut cache).is_err());
        }

        assert_eq!(memory.protects.len(), failure_call);
        assert_eq!(memory.releases, [allocation_id]);
        assert_eq!(
            memory.abort_progress,
            [MutationProgress::ProtectionModified]
        );
    }
}

#[test]
fn partial_protection_apply_poisons_a_fixed_image() {
    let (bytes, _) = image_with_bss_and_gap(ET_EXEC);
    let allocation_id = AllocationId::new(307);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x1000),
        0x3000,
        0x1000,
        AllocationOwnership::BorrowedFixed,
    ));
    memory.fail_protect_at = Some(1);
    let mut cache = FakeCodeCache::default();
    let request = ArtifactRequest::new(
        ExpectedElfType::Exec,
        test_riscv64_profile(),
        LoadLimits::default(),
    );

    assert!(crate::load_image(
        SliceElfReader::new(&bytes),
        request,
        &mut memory,
        &mut cache,
        &Riscv64Relocator,
    )
    .is_err());
    assert_eq!(memory.protects.len(), 1);
    assert_eq!(memory.releases, [allocation_id]);
    assert_eq!(
        memory.abort_progress,
        [MutationProgress::ProtectionModified]
    );
    assert!(memory.fixed_poisoned);
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
        let error = crate::load_image(
            SliceElfReader::new(&bytes),
            riscv64_request(),
            &mut memory,
            &mut cache,
            &Riscv64Relocator,
        )
        .unwrap_err();
        assert_eq!(error.stage(), LoadStage::Metadata);
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
    let error = crate::load_image(
        SliceElfReader::new(&bytes),
        riscv64_request(),
        &mut memory,
        &mut cache,
        &Riscv64Relocator,
    )
    .unwrap_err();
    assert_eq!(error.stage(), LoadStage::Relocate);
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

    let receipt = crate::load_image(
        SliceElfReader::new(&bytes),
        request,
        &mut memory,
        &mut cache,
        &Riscv64Relocator,
    )
    .unwrap();

    assert_eq!(receipt.entry.get(), 0x8000);
    assert_eq!(receipt.relocation_count, 1);
    assert!(memory.releases.is_empty());
    assert!(memory.installed_lease.is_some());

    memory.release_installed();
    assert!(memory.releases.is_empty());
    assert_eq!(memory.committed_releases, [AllocationId::new(26)]);
    assert!(memory.installed_lease.is_none());
}

#[test]
fn dropping_every_public_stage_aborts_exactly_once_with_the_latest_progress() {
    let bytes = riscv_image_with_relro();
    let new_memory = |id| {
        FakeMemory::returning(ImageAllocation::new(
            AllocationId::new(id),
            TargetAddr::new(0x8000),
            0x3000,
            0x1000,
            AllocationOwnership::Owned,
        ))
    };
    let assert_aborted = |memory: &FakeMemory, id, progress| {
        assert_eq!(memory.releases, [AllocationId::new(id)]);
        assert_eq!(memory.abort_progress, [progress]);
        assert!(memory.installed_lease.is_none());
    };

    let mut memory = new_memory(320);
    drop(reserved_stage(&bytes, &mut memory));
    assert_aborted(&memory, 320, MutationProgress::Reserved);

    let mut memory = new_memory(321);
    drop(mapped_stage(&bytes, &mut memory));
    assert_aborted(&memory, 321, MutationProgress::BytesModified);

    let mut memory = new_memory(322);
    drop(runtime_stage(&bytes, &mut memory));
    assert_aborted(&memory, 322, MutationProgress::BytesModified);

    let mut memory = new_memory(323);
    drop(relocated_stage(&bytes, &mut memory));
    assert_aborted(&memory, 323, MutationProgress::BytesModified);

    let mut memory = new_memory(324);
    let mut cache = FakeCodeCache::default();
    drop(prepared_stage(&bytes, &mut memory, &mut cache));
    assert_aborted(&memory, 324, MutationProgress::ProtectionModified);

    let mut memory = new_memory(325);
    let mut cache = FakeCodeCache::default();
    let ready = prepared_stage(&bytes, &mut memory, &mut cache)
        .prepare_commit()
        .unwrap();
    drop(ready);
    assert_aborted(&memory, 325, MutationProgress::ProtectionModified);
}

#[test]
fn prepare_install_failure_keeps_rollback_armed() {
    let bytes = riscv_image_with_relro();
    let allocation_id = AllocationId::new(29);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8000),
        0x3000,
        0x1000,
        AllocationOwnership::Owned,
    ));
    memory.fail_prepare_install = true;
    let mut cache = FakeCodeCache::default();

    let error = crate::load_image(
        SliceElfReader::new(&bytes),
        riscv64_request(),
        &mut memory,
        &mut cache,
        &Riscv64Relocator,
    )
    .unwrap_err();

    assert_eq!(error.kind(), LoadErrorKind::Backend);
    assert_eq!(error.stage(), LoadStage::Publish);
    assert_eq!(memory.releases, [allocation_id]);
    assert_eq!(
        memory.abort_progress,
        [MutationProgress::ProtectionModified]
    );
    assert!(memory.installed_lease.is_none());
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
        &Riscv64Relocator,
    )
    .unwrap_err();

    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
    assert_eq!(memory.releases, [allocation_id]);
}
