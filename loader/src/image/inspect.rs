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

use alloc::boxed::Box;

use crate::{
    address::{FileRange, TargetAddress, TargetRange},
    elf::{DynamicSegmentInfo, ElfHeaderInfo, LoadSegmentInfo},
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage, ProgramHeaderField},
    identity::{ElfMachine, LoadRequest},
    image::{admit::program_header_error, plan::PlannedImage},
    reader::ElfReader,
    MemoryPermissions,
};

#[derive(PartialEq)]
pub(crate) enum StackKind {
    NotDeclared,
    NonExecutable,
    Executable,
}

pub(crate) struct InspectedImage<R: ElfReader> {
    reader: R,
    request: LoadRequest,
    header: ElfHeaderInfo,
    load_segments: Box<[LoadSegmentInfo]>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack: StackKind,
    interpreter: Option<FileRange>,
    tls: Option<TargetRange>,
}

impl<R: ElfReader> InspectedImage<R> {
    #[inline]
    pub const fn new(
        reader: R,
        request: LoadRequest,
        header: ElfHeaderInfo,
        load_segments: Box<[LoadSegmentInfo]>,
        dynamic: Option<DynamicSegmentInfo>,
        relro: Option<TargetRange>,
        stack: StackKind,
        interpreter: Option<FileRange>,
        tls: Option<TargetRange>,
    ) -> Self {
        Self {
            reader,
            request,
            header,
            load_segments,
            dynamic,
            relro,
            stack,
            interpreter,
            tls,
        }
    }

    pub fn plan(mut self) -> LoadResult<PlannedImage<R>> {
        let mut r = 0;
        for segment in self.load_segments.iter() {
            if segment.memory_size() == 0 {
                continue;
            }
            r += 1;
            let align = normalize_alignment(segment.align(), segment.index())
                .map_err(|error| error.at_stage(LoadStage::Plan))?;
            self.request
                .limits()
                .check_segment_alignment(align)
                .map_err(|error| error.at_stage(LoadStage::Plan))?;
            if segment.file_range().offset() % align != segment.vaddr().get() % align {
                return Err(program_header_error(
                    segment.index(),
                    ProgramHeaderField::Align,
                    align,
                )
                .at_stage(LoadStage::Plan));
            }
            if segment.permissions().contains(MemoryPermissions::WRITE)
                && segment.permissions().contains(MemoryPermissions::EXECUTE)
            {
                return Err(LoadError::new(
                    LoadErrorKind::PermissionConflict,
                    ErrorContext::ProgramHeader {
                        index: segment.index(),
                        field: ProgramHeaderField::VirtualRange,
                        value: segment.vaddr().get(),
                    },
                )
                .at_stage(LoadStage::Plan));
            }
        }
        if r == 0 {
            return Err(
                LoadError::new(LoadErrorKind::BadElf, ErrorContext::None).at_stage(LoadStage::Plan)
            );
        }

        self.load_segments
            .sort_unstable_by_key(|segment| segment.vaddr().get());
        for pair in self.load_segments.windows(2) {
            let vaddr_range1 = TargetRange::new(pair[0].vaddr(), pair[0].memory_size());
            let vaddr_range2 = TargetRange::new(pair[1].vaddr(), pair[1].memory_size());
            if vaddr_range1.overlaps(vaddr_range2) {
                return Err(program_header_error(
                    pair[1].index(),
                    ProgramHeaderField::VirtualRange,
                    pair[1].vaddr().get(),
                )
                .at_stage(LoadStage::Plan));
            }
        }
        let segment_max_align = self
            .load_segments
            .iter()
            .map(|segment| segment.align())
            .max()
            .unwrap_or(1);
        let min_vaddr = self.load_segments[0].vaddr();
        let max_vaddr = self
            .load_segments
            .iter()
            .map(|segment| segment.vaddr().checked_add(segment.memory_size()))
            .try_fold(TargetAddress::new(0), |current, next| {
                let next = next.map_err(|e| e.at_stage(LoadStage::Plan))?;
                Ok::<_, LoadError>(core::cmp::max(current, next))
            })?;
        let aligned_min_vaddr = min_vaddr
            .align_down(segment_max_align)
            .map_err(|e| e.at_stage(LoadStage::Plan))?;
        let aligned_max_vaddr = max_vaddr
            .align_up(segment_max_align)
            .map_err(|e| e.at_stage(LoadStage::Plan))?;
        let image_span = aligned_max_vaddr
            .checked_sub(aligned_min_vaddr)
            .map_err(|e| e.at_stage(LoadStage::Plan))?;
        self.request
            .limits()
            .check_image_span(image_span)
            .map_err(|error| error.at_stage(LoadStage::Plan))?;

        let entry_vaddr = TargetAddress::new(self.header.entry());
        let canonical_entry_vaddr = canonical_entry(entry_vaddr, self.header.machine());
        let executable = self.load_segments.iter().any(|segment| {
            segment.permissions().contains(MemoryPermissions::EXECUTE)
                && TargetRange::new(segment.vaddr(), segment.memory_size())
                    .contains_span(canonical_entry_vaddr, 1)
        });
        if !executable {
            return Err(LoadError::new(
                LoadErrorKind::PermissionConflict,
                ErrorContext::TargetRange {
                    start: canonical_entry_vaddr,
                    len: 1,
                    align: 0,
                },
            )
            .at_stage(LoadStage::Plan));
        }

        if let Some(relro) = self.relro {
            let valid_relro = self.load_segments.iter().any(|segment| {
                TargetRange::new(segment.vaddr(), segment.memory_size())
                    .contains_span(relro.start(), relro.len())
                    && segment.permissions().contains(MemoryPermissions::WRITE)
            });
            if !valid_relro {
                return Err(LoadError::new(
                    LoadErrorKind::PermissionConflict,
                    ErrorContext::TargetRange {
                        start: relro.start(),
                        len: relro.len(),
                        align: 0,
                    },
                )
                .at_stage(LoadStage::Plan));
            }
        }

        Ok(PlannedImage::new(
            self.reader,
            self.request,
            aligned_min_vaddr,
            aligned_max_vaddr,
            image_span,
            segment_max_align,
            entry_vaddr,
            canonical_entry_vaddr,
            self.load_segments,
            self.dynamic,
            self.relro,
            self.stack,
            self.interpreter,
            self.tls,
        ))
    }
}

fn canonical_entry(entry: TargetAddress, machine: ElfMachine) -> TargetAddress {
    if machine == ElfMachine::Arm {
        TargetAddress::new(entry.get() & !1)
    } else {
        entry
    }
}

fn normalize_alignment(align: u64, index: u16) -> LoadResult<u64> {
    match align {
        0 | 1 => Ok(1),
        value if value.is_power_of_two() => Ok(value),
        value => Err(LoadError::new(
            LoadErrorKind::InvalidAlignment,
            ErrorContext::ProgramHeader {
                index,
                field: ProgramHeaderField::Align,
                value,
            },
        )),
    }
}
