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
    dynamic::{DT_DEBUG, DT_FLAGS_1, DT_NEEDED, DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ},
    header::{EI_CLASS, EI_DATA, ELFCLASS32, ELFDATA2MSB, EM_ARM, EM_RISCV, ET_DYN, ET_EXEC},
    Elf,
};

use self::fixture::ElfFixtureBuilder;
use crate::{
    AllocationId, AllocationOwnership, AllocationRequest, ArtifactProfile, ArtifactRequest,
    ElfClass, ElfReader, Endian, ErrorContext, ExpectedElfType, ImageAllocation,
    ImageLoadTransaction, ImageLoader, ImageMemory, LoadError, LoadErrorKind, LoadLimits,
    LoadResult, LoadStage, MemoryPermissions, Placement, PlannedArtifact, RelocationAddend,
    Riscv64Relocator, RuntimeFeaturePolicy, SliceElfReader, TargetAddr, TargetLocation,
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
        let start = location.offset() as usize;
        self.bytes[start..start + data.len()].copy_from_slice(data);
        self.writes.push((location, data.len()));
        Ok(())
    }

    fn zero(&mut self, location: TargetLocation, len: u64) -> LoadResult<()> {
        self.validate_access(location, len, MemoryPermissions::WRITE)?;
        let start = location.offset() as usize;
        self.bytes[start..start + len as usize].fill(0);
        self.zeros.push((location, len));
        Ok(())
    }

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> LoadResult<()> {
        self.validate_access(location, dst.len() as u64, MemoryPermissions::READ)?;
        let start = location.offset() as usize;
        dst.copy_from_slice(&self.bytes[start..start + dst.len()]);
        Ok(())
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
    let planned = planned_image(&bytes, ExpectedElfType::Dyn);
    let allocation_id = AllocationId::new(9);
    let mut memory = FakeMemory::returning(ImageAllocation::new(
        allocation_id,
        TargetAddr::new(0x8001),
        0x800,
        1,
        AllocationOwnership::Owned,
    ));

    {
        let mut transaction = ImageLoadTransaction::new(&mut memory);
        let error = ImageLoader::new()
            .reserve(planned, &mut transaction)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::Backend);
    }

    assert_eq!(memory.releases, [allocation_id]);
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
