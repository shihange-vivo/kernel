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

use goblin::elf::{
    header::{EM_ARM, EM_RISCV, ET_DYN},
    Elf,
};

use crate::tests::fixture::ElfFixtureBuilder;

mod fixture;

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
fn fixture_builder_emits_a_parseable_elf32_header() {
    let bytes = ElfFixtureBuilder::elf32(EM_ARM, ET_DYN).build();
    let elf = Elf::parse(&bytes).expect("fixture must contain a valid ELF header");

    assert_eq!(elf.header.e_machine, EM_ARM);
    assert_eq!(elf.header.e_type, ET_DYN);
    assert!(!elf.is_64);
    assert!(elf.little_endian);
}

mod placement {
    use crate::{
        address::{TargetAddress, TargetRange},
        memory::{AllocationRequest, Placement},
    };

    #[test]
    fn anywhere_request_reports_no_fixed_range() {
        let request = AllocationRequest::new(Placement::Anywhere, 0x1000, 0x100);
        assert!(matches!(request.placement(), Placement::Anywhere));
        assert_eq!(request.size(), 0x1000);
        assert_eq!(request.align(), 0x100);
    }

    #[test]
    fn fixed_request_carries_its_range() {
        let range = TargetRange::new(TargetAddress::new(0x5000_0000), 0x2000);
        let request = AllocationRequest::new(Placement::Fixed(range), 0x2000, 0x100);
        match request.placement() {
            Placement::Fixed(actual) => {
                assert_eq!(actual.start(), TargetAddress::new(0x5000_0000));
                assert_eq!(actual.len(), 0x2000);
            }
            other => panic!("expected fixed placement, got {other:?}"),
        }
        assert_eq!(request.size(), 0x2000);
    }
}

mod exec_plan {
    use std::{cell::RefCell, rc::Rc, vec::Vec};

    use crate::{
        identity::{ElfClass, ElfData, ElfMachine, ElfType, LoadLimits, LoadProfile, LoadRequest},
        image::ImageLoader,
        memory::Placement,
        reader::SliceElfReader,
        tests::fixture::{ElfFixtureBuilder, RecordingMemory},
    };

    fn build_exec_request() -> LoadRequest {
        let profile = LoadProfile::new(
            ElfClass::Elf64,
            ElfData::Little,
            ElfMachine::Riscv,
            ElfType::Exec,
        );
        LoadRequest::new(profile, LoadLimits::DEFAULT)
    }

    fn exec_bytes() -> Vec<u8> {
        // Single PT_LOAD r-x segment at 0x5000_0000. p_offset matches p_vaddr
        // mod p_align (4) so inspect's alignment check passes. Entry lives
        // inside the only segment so plan() accepts it.
        ElfFixtureBuilder::elf64(goblin::elf::header::EM_RISCV, goblin::elf::header::ET_EXEC)
            .with_load_segment(0x5000_0000, 0x100, 0x100, 0x4)
            .with_entry(0x5000_0000)
            .build()
    }

    #[test]
    fn exec_image_records_fixed_placement() {
        let bytes = exec_bytes();
        let planned = ImageLoader::new(SliceElfReader::new(&bytes), build_exec_request())
            .admit()
            .expect("admit")
            .inspect()
            .expect("inspect")
            .plan()
            .expect("plan must accept ET_EXEC with fixed placement");

        let sink = Rc::new(RefCell::new(None));
        let recording = RecordingMemory::new(Rc::clone(&sink));
        let _ = planned.allocate(recording).expect("allocate");

        let recorded = RecordingMemory::recorded(&sink).expect("request was recorded");
        match recorded.placement() {
            Placement::Fixed(range) => {
                assert_eq!(range.start().get(), 0x5000_0000);
                assert_eq!(range.len(), 0x100);
            }
            other => panic!("expected fixed placement, got {other:?}"),
        }
        assert_eq!(recorded.size(), 0x100);
    }
}

mod fixed_mapper {
    use crate::{
        address::{TargetAddress, TargetRange},
        memory::{AllocationRequest, ImageMemory, Placement},
        memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion},
    };

    // SAFETY: test-only static region. Unit tests only exercise the
    // allocate/validate paths; the span 0x5000_0000..0x5000_2000 is never
    // dereferenced on the host.
    static REGIONS: [MemoryRegion; 1] = [unsafe {
        MemoryRegion::new(
            0x5000_0000,
            0x5000_2000,
            MemoryPermissions::READ
                .bitor(MemoryPermissions::WRITE)
                .bitor(MemoryPermissions::EXECUTE),
        )
    }];

    fn fixed_request(start: u64, len: u64) -> AllocationRequest {
        AllocationRequest::new(
            Placement::Fixed(TargetRange::new(TargetAddress::new(start), len)),
            len,
            4,
        )
    }

    #[test]
    fn fixed_mapper_allocates_borrowed_span() {
        let mut mapper = MemoryMapper::new(Some(&REGIONS));
        let lease = mapper
            .allocate_image(fixed_request(0x5000_0000, 0x1000))
            .expect("allocate");
        let allocation = lease.allocation();
        assert_eq!(allocation.base().get(), 0x5000_0000);
        assert_eq!(allocation.len(), 0x1000);
        assert_eq!(allocation.align(), 4);
        mapper.abort_image(lease, crate::memory::MutationProgress::Reserved);
    }

    #[test]
    fn fixed_mapper_rejects_span_exceeding_regions() {
        let mut mapper = MemoryMapper::new(Some(&REGIONS));
        // The region ends at 0x5000_2000; a span of 0x3000 overruns it.
        assert!(mapper
            .allocate_image(fixed_request(0x5000_0000, 0x3000))
            .is_err());
    }

    #[test]
    fn fixed_mapper_rejects_span_outside_regions() {
        let mut mapper = MemoryMapper::new(Some(&REGIONS));
        assert!(mapper
            .allocate_image(fixed_request(0x6000_0000, 0x1000))
            .is_err());
    }

    #[test]
    fn allocated_mapper_rejects_fixed_request() {
        let mut mapper = MemoryMapper::new(None);
        assert!(mapper
            .allocate_image(fixed_request(0x5000_0000, 0x1000))
            .is_err());
    }

    #[test]
    fn fixed_mapper_rejects_anywhere_request() {
        let mut mapper = MemoryMapper::new(Some(&REGIONS));
        let request = AllocationRequest::new(Placement::Anywhere, 0x1000, 4);
        assert!(mapper.allocate_image(request).is_err());
    }
}

mod entry_dispatch {
    use std::vec::Vec;

    use crate::{load_elf, memory_mapper::MemoryMapper, tests::fixture::ElfFixtureBuilder};

    #[test]
    fn exec_image_on_allocated_mapper_is_rejected() {
        // An ET_EXEC image must only be given to a Fixed mapper; the entry
        // dispatch notices the mismatch before any segment is copied.
        let bytes =
            ElfFixtureBuilder::elf64(goblin::elf::header::EM_RISCV, goblin::elf::header::ET_EXEC)
                .with_load_segment(0x5000_0000, 0x100, 0x100, 0x4)
                .with_entry(0x5000_0000)
                .build();
        let mut mapper = MemoryMapper::new(None);
        let result = load_elf(&bytes, &mut mapper);
        assert!(result.is_err());
    }
}
