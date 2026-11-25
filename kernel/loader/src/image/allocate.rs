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

//! Populate prepared segment backing through the memory backend.

use super::map::MappedImage;
use crate::{
    elf::{DynamicInfo, LoadSegmentInfo},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    memory::{AllocationOffset, ImageMapping, MemoryPermissions, TargetAddress, TargetRange},
    profile::LoadProfile,
    reader::ElfReader,
    LoadError, LoadResult, ProgramHeaderTable,
};
use alloc::vec::Vec;

const COPY_BUFFER_SIZE: usize = 512;

#[must_use = "dropping a prepared image releases its allocation"]
pub(crate) struct AllocatedImage<R: ElfReader, A: ImageMapping> {
    reader: R,
    allocation: A,
    profile: LoadProfile,
    entry: TargetAddress,
    program_header_offset: u64,
    program_header_entry_size: u16,
    program_header_count: u16,
    segments: Vec<LoadSegmentInfo>,
    dynamic: Option<DynamicInfo>,
    relro: Option<TargetRange>,
    /// Start of the planned span in the ELF virtual address space.
    image_start: TargetAddress,
}

impl<R: ElfReader, A: ImageMapping> AllocatedImage<R, A> {
    pub(super) const fn new(
        reader: R,
        allocation: A,
        profile: LoadProfile,
        entry: TargetAddress,
        program_header_offset: u64,
        program_header_entry_size: u16,
        program_header_count: u16,
        segments: Vec<LoadSegmentInfo>,
        dynamic: Option<DynamicInfo>,
        relro: Option<TargetRange>,
        image_start: TargetAddress,
    ) -> Self {
        Self {
            reader,
            allocation,
            profile,
            entry,
            program_header_offset,
            program_header_entry_size,
            program_header_count,
            segments,
            dynamic,
            relro,
            image_start,
        }
    }

    /// Populate the mapping and release the source reader.
    pub(crate) fn map(self) -> LoadResult<MappedImage<A>> {
        self.map_with(|image, _reader| image)
    }

    /// Populate the mapping and return the source reader for further ELF reads.
    #[cfg(enable_dynamic_linker)]
    pub(crate) fn map_with_reader(self) -> LoadResult<(MappedImage<A>, R)> {
        self.map_with(|image, reader| (image, reader))
    }

    pub(crate) const fn allocation(&self) -> &A {
        &self.allocation
    }

    fn map_with<T>(self, finish: impl FnOnce(MappedImage<A>, R) -> T) -> LoadResult<T> {
        self.map_inner(finish)
            .map_err(|error| error.at_stage(LoadStage::Map))
    }

    fn map_inner<T>(mut self, finish: impl FnOnce(MappedImage<A>, R) -> T) -> LoadResult<T> {
        let base = self.allocation.base();
        // Some embedded images leave the table outside their PT_LOAD ranges;
        // loading them remains valid, but a standard startup cannot use AT_PHDR.
        let mut program_headers = None;
        let table_len =
            u64::from(self.program_header_entry_size) * u64::from(self.program_header_count);
        if table_len != 0 {
            for segment in &self.segments {
                let file = segment.file_range();
                if segment.permissions().contains(MemoryPermissions::READ)
                    && let Some(offset) = self.program_header_offset.checked_sub(file.offset())
                    && offset <= file.len()
                    && table_len <= file.len() - offset
                {
                    let offset = segment
                        .vaddr()
                        .checked_sub(self.image_start)?
                        .checked_add(offset)
                        .ok_or_else(|| {
                            LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None)
                        })?;
                    program_headers = Some(ProgramHeaderTable::new(
                        base.checked_add(offset)?,
                        self.program_header_entry_size,
                        self.program_header_count,
                    ));
                    break;
                }
            }
        }
        let entry = if self.entry.get() == 0 {
            None
        } else {
            let entry_offset = self.entry.checked_sub(self.image_start)?;
            let entry = base.checked_add(entry_offset)?;
            let entry_mode = self.profile.entry_mode();
            let instruction_alignment = u64::from(entry_mode.instruction_alignment());
            // p_align may be weaker than instruction alignment. Check the actual
            // relocated entry before any bytes are read or destinations modified.
            if entry
                .get()
                .checked_rem(instruction_alignment)
                .is_some_and(|remainder| remainder != 0)
            {
                return Err(LoadError::new(
                    LoadErrorKind::InvalidAlignment,
                    ErrorContext::TargetRange {
                        start: entry,
                        len: u64::from(entry_mode.minimum_instruction_size()),
                        align: instruction_alignment,
                    },
                ));
            }
            Some(entry)
        };
        let mut scratch = [0; COPY_BUFFER_SIZE];
        for segment in &self.segments {
            let offset = AllocationOffset::new(segment.vaddr().checked_sub(self.image_start)?);
            let file = segment.file_range();
            let mut copied = 0;
            while copied < file.len() {
                let len = (file.len() - copied).min(COPY_BUFFER_SIZE as u64) as usize;
                let file_offset = file.offset().checked_add(copied).ok_or_else(|| {
                    LoadError::new(
                        LoadErrorKind::IntegerOverflow,
                        ErrorContext::FileRange {
                            offset: file.offset(),
                            len: file.len(),
                            file_len: 0,
                        },
                    )
                })?;
                self.reader
                    .read_exact_at(file_offset, &mut scratch[..len])?;
                self.allocation
                    .write(offset.checked_add(copied)?, &scratch[..len])?;
                copied += len as u64;
            }
            let bss_len = segment
                .memory_size()
                .checked_sub(file.len())
                .ok_or_else(|| {
                    LoadError::new(
                        LoadErrorKind::BadElf,
                        ErrorContext::TargetRange {
                            start: segment.vaddr(),
                            len: segment.memory_size(),
                            align: segment.align(),
                        },
                    )
                })?;
            if bss_len != 0 {
                self.allocation
                    .zero(offset.checked_add(file.len())?, bss_len)?;
            }
        }
        // Every payload copy and BSS clear must finish before any segment
        // loses its initialization write access. RELRO remains writable for
        // relocation; seal() removes its WRITE permission separately.
        // Revoke the reservation first, so restoring segment permissions leaves
        // every hole and alignment-padding byte at NONE.
        let len = self.allocation.len();
        self.allocation
            .set_permissions(AllocationOffset::new(0), len, MemoryPermissions::NONE)
            .map_err(|error| {
                error.with_context(ErrorContext::MemoryAccess {
                    allocation_base: base,
                    allocation_len: len,
                    allocation_align: self.allocation.align(),
                    offset: 0,
                    len,
                })
            })?;
        for segment in &self.segments {
            let offset = AllocationOffset::new(segment.vaddr().checked_sub(self.image_start)?);
            self.allocation
                .set_permissions(offset, segment.memory_size(), segment.permissions())
                .map_err(|error| {
                    error.with_context(ErrorContext::MemoryAccess {
                        allocation_base: base,
                        allocation_len: len,
                        allocation_align: self.allocation.align(),
                        offset: offset.value(),
                        len: segment.memory_size(),
                    })
                })?;
        }
        let image = MappedImage::new(
            program_headers,
            self.allocation,
            self.profile,
            self.segments,
            self.dynamic,
            self.relro,
            self.image_start,
            entry,
        );
        Ok(finish(image, self.reader))
    }
}
