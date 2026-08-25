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

use alloc::{boxed::Box, vec::Vec};

use crate::{
    AdmittedArtifact, ElfReader, ErrorContext, FileRange, ImageKind, ImageLoader, LoadError,
    LoadErrorKind, LoadLimits, LoadResult, LoadStage, MemoryPermissions, ParsedImage,
    ProgramHeaderField, TargetAddr, TargetRange,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentLayout {
    source_index: u16,
    vaddr_range: TargetRange,
    file_range: FileRange,
    align: u64,
    permissions: MemoryPermissions,
}

impl SegmentLayout {
    pub const fn source_index(&self) -> u16 {
        self.source_index
    }

    pub const fn vaddr_range(&self) -> TargetRange {
        self.vaddr_range
    }

    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    pub const fn align(&self) -> u64 {
        self.align
    }

    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}

#[derive(Debug)]
pub struct ImageLayout {
    aligned_min_vaddr: TargetAddr,
    aligned_max_vaddr: TargetAddr,
    image_span: u64,
    max_align: u64,
    entry_vaddr: TargetAddr,
    canonical_entry_vaddr: TargetAddr,
    segments: Box<[SegmentLayout]>,
    relro: Option<TargetRange>,
}

impl ImageLayout {
    pub const fn aligned_min_vaddr(&self) -> TargetAddr {
        self.aligned_min_vaddr
    }

    pub const fn aligned_max_vaddr(&self) -> TargetAddr {
        self.aligned_max_vaddr
    }

    pub const fn image_span(&self) -> u64 {
        self.image_span
    }

    pub const fn max_align(&self) -> u64 {
        self.max_align
    }

    pub const fn entry_vaddr(&self) -> TargetAddr {
        self.entry_vaddr
    }

    pub const fn canonical_entry_vaddr(&self) -> TargetAddr {
        self.canonical_entry_vaddr
    }

    pub fn segments(&self) -> &[SegmentLayout] {
        &self.segments
    }

    pub const fn relro(&self) -> Option<TargetRange> {
        self.relro
    }

    pub fn load_bias_for(
        &self,
        mapped_base: TargetAddr,
        kind: ImageKind,
    ) -> LoadResult<TargetAddr> {
        match kind {
            ImageKind::StaticPie => Ok(TargetAddr::new(
                mapped_base.checked_sub(self.aligned_min_vaddr)?,
            )),
            ImageKind::FixedExec if mapped_base == self.aligned_min_vaddr => Ok(TargetAddr::new(0)),
            ImageKind::FixedExec => Err(LoadError::new(
                LoadStage::Plan,
                LoadErrorKind::OutOfBounds,
                ErrorContext::TargetRange {
                    start: mapped_base,
                    len: self.image_span,
                },
            )),
        }
    }

    pub fn locate_vaddr_range(
        &self,
        vaddr: TargetAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<SegmentLocation> {
        self.segments
            .iter()
            .enumerate()
            .find_map(|(index, segment)| {
                if segment.vaddr_range.contains_span(vaddr, len)
                    && segment.permissions.contains(permissions)
                {
                    Some(SegmentLocation {
                        segment_index: index,
                        offset_in_segment: vaddr.get() - segment.vaddr_range.start().get(),
                    })
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                LoadError::new(
                    LoadStage::Plan,
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange { start: vaddr, len },
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentLocation {
    segment_index: usize,
    offset_in_segment: u64,
}

impl SegmentLocation {
    pub const fn segment_index(self) -> usize {
        self.segment_index
    }

    pub const fn offset_in_segment(self) -> u64 {
        self.offset_in_segment
    }
}

#[derive(Debug)]
pub struct PlannedArtifact<R> {
    artifact: AdmittedArtifact<R>,
    parsed: ParsedImage,
    layout: ImageLayout,
}

impl<R> PlannedArtifact<R> {
    pub const fn artifact(&self) -> &AdmittedArtifact<R> {
        &self.artifact
    }

    pub const fn parsed(&self) -> &ParsedImage {
        &self.parsed
    }

    pub const fn layout(&self) -> &ImageLayout {
        &self.layout
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ImageLayoutBuilder;

impl ImageLayoutBuilder {
    pub fn build(parsed: &ParsedImage, limits: &LoadLimits) -> LoadResult<ImageLayout> {
        limits.check_load_segment_count(parsed.load_segments().len())?;
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(parsed.load_segments().len())
            .map_err(|_| {
                LoadError::new(
                    LoadStage::Plan,
                    LoadErrorKind::OutOfMemory,
                    ErrorContext::None,
                )
            })?;

        for segment in parsed.load_segments() {
            if segment.file_range().len() > segment.memory_size() {
                return Err(program_header_error(
                    segment.index(),
                    ProgramHeaderField::FileRange,
                    segment.file_range().len(),
                ));
            }
            if segment.memory_size() == 0 {
                continue;
            }
            let align = normalize_alignment(segment.align(), segment.index())?;
            if segment.file_range().offset() % align != segment.vaddr().get() % align {
                return Err(program_header_error(
                    segment.index(),
                    ProgramHeaderField::VirtualRange,
                    align,
                ));
            }
            let vaddr_range = TargetRange::new(segment.vaddr(), segment.memory_size());
            vaddr_range.end()?;
            if segment.permissions().contains(MemoryPermissions::WRITE)
                && segment.permissions().contains(MemoryPermissions::EXECUTE)
            {
                return Err(LoadError::new(
                    LoadStage::Plan,
                    LoadErrorKind::PermissionConflict,
                    ErrorContext::ProgramHeader {
                        index: segment.index(),
                        field: ProgramHeaderField::VirtualRange,
                        value: segment.vaddr().get(),
                    },
                ));
            }
            segments.push(SegmentLayout {
                source_index: segment.index(),
                vaddr_range,
                file_range: segment.file_range(),
                align,
                permissions: segment.permissions(),
            });
        }
        if segments.is_empty() {
            return Err(LoadError::new(
                LoadStage::Plan,
                LoadErrorKind::BadElf,
                ErrorContext::None,
            ));
        }

        segments.sort_unstable_by_key(|segment| segment.vaddr_range.start());
        for pair in segments.windows(2) {
            if pair[0].vaddr_range.overlaps(pair[1].vaddr_range) {
                return Err(program_header_error(
                    pair[1].source_index,
                    ProgramHeaderField::VirtualRange,
                    pair[1].vaddr_range.start().get(),
                ));
            }
        }

        let max_align = segments
            .iter()
            .map(|segment| segment.align)
            .max()
            .unwrap_or(1);
        let min_vaddr = segments[0].vaddr_range.start();
        let max_vaddr = segments
            .iter()
            .map(|segment| segment.vaddr_range.end())
            .try_fold(TargetAddr::new(0), |current, next| {
                let next = next?;
                Ok::<_, LoadError>(core::cmp::max(current, next))
            })?;
        let aligned_min_vaddr = min_vaddr.align_down(max_align)?;
        let aligned_max_vaddr = max_vaddr.align_up(max_align)?;
        let image_span = aligned_max_vaddr.checked_sub(aligned_min_vaddr)?;
        limits.check_image_span(image_span)?;

        let entry_vaddr = TargetAddr::new(parsed.header().entry());
        let canonical_entry_vaddr = canonical_entry(entry_vaddr, parsed.header().machine());
        let executable = segments.iter().any(|segment| {
            segment.permissions.contains(MemoryPermissions::EXECUTE)
                && segment.vaddr_range.contains_span(canonical_entry_vaddr, 1)
        });
        if !executable {
            return Err(LoadError::new(
                LoadStage::Plan,
                LoadErrorKind::PermissionConflict,
                ErrorContext::TargetRange {
                    start: entry_vaddr,
                    len: 1,
                },
            ));
        }

        if let Some(relro) = parsed.relro() {
            let valid_relro = segments.iter().any(|segment| {
                segment
                    .vaddr_range
                    .contains_span(relro.start(), relro.len())
                    && segment.permissions.contains(MemoryPermissions::WRITE)
            });
            if !valid_relro {
                return Err(LoadError::new(
                    LoadStage::Plan,
                    LoadErrorKind::PermissionConflict,
                    ErrorContext::TargetRange {
                        start: relro.start(),
                        len: relro.len(),
                    },
                ));
            }
        }

        Ok(ImageLayout {
            aligned_min_vaddr,
            aligned_max_vaddr,
            image_span,
            max_align,
            entry_vaddr,
            canonical_entry_vaddr,
            segments: segments.into_boxed_slice(),
            relro: parsed.relro(),
        })
    }
}

impl ImageLoader {
    pub fn plan<R: ElfReader>(
        &self,
        admitted: AdmittedArtifact<R>,
    ) -> LoadResult<PlannedArtifact<R>> {
        let parsed = self.inspect(&admitted)?;
        let layout = ImageLayoutBuilder::build(&parsed, admitted.request().limits())?;
        Ok(PlannedArtifact {
            artifact: admitted,
            parsed,
            layout,
        })
    }
}

fn normalize_alignment(align: u64, index: u16) -> LoadResult<u64> {
    match align {
        0 | 1 => Ok(1),
        value if value.is_power_of_two() => Ok(value),
        value => Err(LoadError::new(
            LoadStage::Plan,
            LoadErrorKind::InvalidAlignment,
            ErrorContext::ProgramHeader {
                index,
                field: ProgramHeaderField::VirtualRange,
                value,
            },
        )),
    }
}

fn canonical_entry(entry: TargetAddr, machine: u16) -> TargetAddr {
    if machine == goblin::elf::header::EM_ARM {
        TargetAddr::new(entry.get() & !1)
    } else {
        entry
    }
}

fn program_header_error(index: u16, field: ProgramHeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadStage::Plan,
        LoadErrorKind::BadElf,
        ErrorContext::ProgramHeader {
            index,
            field,
            value,
        },
    )
}
