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

use std::{cell::RefCell, rc::Rc, vec::Vec};

use goblin::{
    elf::header::{
        EI_CLASS, EI_DATA, EI_VERSION, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFMAG, EV_CURRENT,
    },
    elf32, elf64,
};

use crate::memory::{
    AllocationId, AllocationLease, AllocationOwnership, AllocationRequest, ImageAllocation,
    ImageMemory, MutationProgress, Placement,
};

pub struct ElfFixtureBuilder {
    bytes: Vec<u8>,
    ph_count: u16,
    is64: bool,
}

impl ElfFixtureBuilder {
    pub fn elf64(e_machine: u16, e_type: u16) -> Self {
        let mut bytes = std::vec![0; elf64::header::SIZEOF_EHDR];
        bytes[..4].copy_from_slice(ELFMAG);
        bytes[EI_CLASS] = ELFCLASS64;
        bytes[EI_DATA] = ELFDATA2LSB;
        bytes[EI_VERSION] = EV_CURRENT;

        write_u16(&mut bytes, 16, e_type);
        write_u16(&mut bytes, 18, e_machine);
        write_u32(&mut bytes, 20, EV_CURRENT as u32);
        write_u64(&mut bytes, 32, elf64::header::SIZEOF_EHDR as u64);
        write_u16(&mut bytes, 52, elf64::header::SIZEOF_EHDR as u16);
        write_u16(&mut bytes, 54, elf64::program_header::SIZEOF_PHDR as u16);
        write_u16(&mut bytes, 58, elf64::section_header::SIZEOF_SHDR as u16);

        Self {
            bytes,
            ph_count: 0,
            is64: true,
        }
    }

    pub fn elf32(e_machine: u16, e_type: u16) -> Self {
        let mut bytes = std::vec![0; elf32::header::SIZEOF_EHDR];
        bytes[..4].copy_from_slice(ELFMAG);
        bytes[EI_CLASS] = ELFCLASS32;
        bytes[EI_DATA] = ELFDATA2LSB;
        bytes[EI_VERSION] = EV_CURRENT;

        write_u16(&mut bytes, 16, e_type);
        write_u16(&mut bytes, 18, e_machine);
        write_u32(&mut bytes, 20, EV_CURRENT as u32);
        write_u32(&mut bytes, 28, elf32::header::SIZEOF_EHDR as u32); // e_phoff
        write_u16(&mut bytes, 40, elf32::header::SIZEOF_EHDR as u16); // e_ehsize
        write_u16(&mut bytes, 42, elf32::program_header::SIZEOF_PHDR as u16); // e_phentsize
        write_u16(&mut bytes, 46, elf32::section_header::SIZEOF_SHDR as u16); // e_shentsize

        Self {
            bytes,
            ph_count: 0,
            is64: false,
        }
    }

    /// Set `e_flags` (offset 36 for ELF32, 48 for ELF64).
    pub fn with_flags(mut self, flags: u32) -> Self {
        let offset = if self.is64 { 48 } else { 36 };
        write_u32(&mut self.bytes, offset, flags);
        self
    }

    /// Append a PT_LOAD program header. The first call's flags default to
    /// PF_R|PF_X; subsequent calls default to PF_R|PF_W.
    pub fn with_load_segment(self, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> Self {
        if self.is64 {
            self.with_load_segment_64(vaddr, filesz, memsz, align)
        } else {
            self.with_load_segment_32(vaddr, filesz, memsz, align)
        }
    }

    fn with_load_segment_64(mut self, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> Self {
        let ph_offset = elf64::header::SIZEOF_EHDR
            + self.ph_count as usize * elf64::program_header::SIZEOF_PHDR;
        self.bytes
            .resize(ph_offset + elf64::program_header::SIZEOF_PHDR, 0);

        let flags = if self.ph_count == 0 { 0x5 } else { 0x6 }; // PF_R|PF_X or PF_R|PF_W
        write_u32(&mut self.bytes, ph_offset, 1); // p_type = PT_LOAD
        write_u32(&mut self.bytes, ph_offset + 4, flags); // p_flags
        write_u64(&mut self.bytes, ph_offset + 8, ph_offset as u64); // p_offset (right after headers)
        write_u64(&mut self.bytes, ph_offset + 16, vaddr); // p_vaddr
        write_u64(&mut self.bytes, ph_offset + 24, vaddr); // p_paddr
        write_u64(&mut self.bytes, ph_offset + 32, filesz); // p_filesz
        write_u64(&mut self.bytes, ph_offset + 40, memsz); // p_memsz
        write_u64(&mut self.bytes, ph_offset + 48, align); // p_align

        self.ph_count += 1;
        write_u16(&mut self.bytes, 56, self.ph_count);

        // Ensure the file is large enough to cover the segment's file range.
        let file_end = (ph_offset as u64) + elf64::program_header::SIZEOF_PHDR as u64 + filesz;
        if self.bytes.len() < file_end as usize {
            self.bytes.resize(file_end as usize, 0);
        }

        self
    }

    fn with_load_segment_32(mut self, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> Self {
        let ph_offset = elf32::header::SIZEOF_EHDR
            + self.ph_count as usize * elf32::program_header::SIZEOF_PHDR;
        self.bytes
            .resize(ph_offset + elf32::program_header::SIZEOF_PHDR, 0);

        let flags = if self.ph_count == 0 { 0x5 } else { 0x6 }; // PF_R|PF_X or PF_R|PF_W
        write_u32(&mut self.bytes, ph_offset, 1); // p_type = PT_LOAD
        write_u32(&mut self.bytes, ph_offset + 4, ph_offset as u32); // p_offset
        write_u32(&mut self.bytes, ph_offset + 8, vaddr as u32); // p_vaddr
        write_u32(&mut self.bytes, ph_offset + 12, vaddr as u32); // p_paddr
        write_u32(&mut self.bytes, ph_offset + 16, filesz as u32); // p_filesz
        write_u32(&mut self.bytes, ph_offset + 20, memsz as u32); // p_memsz
        write_u32(&mut self.bytes, ph_offset + 24, flags); // p_flags
        write_u32(&mut self.bytes, ph_offset + 28, align as u32); // p_align

        self.ph_count += 1;
        write_u16(&mut self.bytes, 44, self.ph_count); // e_phnum

        // Ensure the file is large enough to cover the segment's file range.
        let file_end = (ph_offset as u64) + elf32::program_header::SIZEOF_PHDR as u64 + filesz;
        if self.bytes.len() < file_end as usize {
            self.bytes.resize(file_end as usize, 0);
        }

        self
    }

    pub fn with_entry(mut self, entry: u64) -> Self {
        if self.is64 {
            write_u64(&mut self.bytes, 24, entry);
        } else {
            write_u32(&mut self.bytes, 24, entry as u32);
        }
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.bytes
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// An `ImageMemory` impl that records the `AllocationRequest` it received
/// into a shared cell, so tests can inspect it after `allocate()` consumes
/// the memory.
pub struct RecordingMemory {
    sink: Rc<RefCell<Option<AllocationRequest>>>,
    allocation: ImageAllocation,
}

impl RecordingMemory {
    pub fn new(sink: Rc<RefCell<Option<AllocationRequest>>>) -> Self {
        Self {
            sink,
            allocation: ImageAllocation::new(crate::address::TargetAddress::new(0), 0, 1),
        }
    }

    pub fn recorded(sink: &Rc<RefCell<Option<AllocationRequest>>>) -> Option<AllocationRequest> {
        *sink.borrow()
    }

    fn validate_allocation(&self, allocation: &ImageAllocation) -> crate::error::LoadResult<()> {
        if allocation == &self.allocation {
            return Ok(());
        }
        Err(crate::error::LoadError::new(
            crate::error::LoadErrorKind::Backend,
            crate::error::ErrorContext::Allocation {
                base: allocation.base(),
                len: allocation.len(),
                align: allocation.align(),
            },
        ))
    }
}

impl ImageMemory for RecordingMemory {
    fn allocate_image(
        &mut self,
        request: AllocationRequest,
    ) -> crate::error::LoadResult<AllocationLease> {
        let (base, ownership) = match request.placement() {
            Placement::Fixed(range) => (range.start(), AllocationOwnership::BorrowedFixed),
            Placement::Anywhere => (
                crate::address::TargetAddress::new(0x1_0000),
                AllocationOwnership::Owned,
            ),
        };
        self.allocation = ImageAllocation::with_identity(
            AllocationId::new(1),
            base,
            request.size(),
            request.align(),
            ownership,
        );
        *self.sink.borrow_mut() = Some(request);
        // SAFETY: the fixture permits only one active allocation and records
        // it immediately above before returning its sole lease.
        Ok(unsafe { AllocationLease::new(self.allocation) })
    }

    fn abort_image(&mut self, _allocation: AllocationLease, _progress: MutationProgress) {}

    fn release_committed(&mut self, _allocation: AllocationLease) {}

    fn image_span(
        &self,
        allocation: &ImageAllocation,
        _offset: crate::memory::AllocationOffset,
        _len: u64,
    ) -> crate::error::LoadResult<*mut u8> {
        self.validate_allocation(allocation)?;
        Ok(core::ptr::null_mut())
    }

    fn write(
        &mut self,
        allocation: &ImageAllocation,
        _offset: crate::memory::AllocationOffset,
        _data: &[u8],
    ) -> crate::error::LoadResult<()> {
        self.validate_allocation(allocation)?;
        Ok(())
    }

    fn zero(
        &mut self,
        allocation: &ImageAllocation,
        _offset: crate::memory::AllocationOffset,
        _len: u64,
    ) -> crate::error::LoadResult<()> {
        self.validate_allocation(allocation)?;
        Ok(())
    }

    fn read(
        &self,
        allocation: &ImageAllocation,
        _offset: crate::memory::AllocationOffset,
        _dst: &mut [u8],
    ) -> crate::error::LoadResult<()> {
        self.validate_allocation(allocation)?;
        Ok(())
    }
}
