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

use alloc::vec::Vec;

use crate::{
    AdmittedArtifact, AllocationRequest, ArtifactFeaturePolicy, ArtifactProfile, ElfReader,
    ErrorContext, ExpectedElfType, FileRange, ImageLoader, LoadError, LoadErrorKind, LoadLimits,
    LoadResult, LoadStage, MemoryPermissions, ParsedImage, Phase0ArtifactPolicy, Placement,
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
    segments: Vec<SegmentLayout>,
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
        expected_elf_type: ExpectedElfType,
    ) -> LoadResult<TargetAddr> {
        match expected_elf_type {
            ExpectedElfType::Dyn => Ok(TargetAddr::new(
                mapped_base
                    .checked_sub(self.aligned_min_vaddr)
                    .map_err(|error| error.at(LoadStage::Plan))?,
            )),
            ExpectedElfType::Exec if mapped_base == self.aligned_min_vaddr => {
                Ok(TargetAddr::new(0))
            }
            ExpectedElfType::Exec => Err(LoadError::new(
                LoadStage::Plan,
                LoadErrorKind::OutOfBounds,
                ErrorContext::TargetRange {
                    start: mapped_base,
                    len: self.image_span,
                },
            )),
        }
    }

    pub const fn allocation_request(
        &self,
        expected_elf_type: ExpectedElfType,
    ) -> AllocationRequest {
        let placement = match expected_elf_type {
            ExpectedElfType::Dyn => Placement::Anywhere,
            ExpectedElfType::Exec => {
                Placement::Fixed(TargetRange::new(self.aligned_min_vaddr, self.image_span))
            }
        };
        AllocationRequest::new(placement, self.image_span, self.max_align)
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

    pub(crate) fn into_parts(self) -> (AdmittedArtifact<R>, ParsedImage, ImageLayout) {
        (self.artifact, self.parsed, self.layout)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ImageLayoutBuilder;

impl ImageLayoutBuilder {
    pub fn build(
        parsed: &ParsedImage,
        profile: &ArtifactProfile,
        limits: &LoadLimits,
    ) -> LoadResult<ImageLayout> {
        limits.check_load_segment_count(parsed.load_segments().len())?;
        let layout_bytes = parsed
            .load_segments()
            .len()
            .checked_mul(
                core::mem::size_of::<crate::LoadSegmentInfo>()
                    + core::mem::size_of::<SegmentLayout>(),
            )
            .and_then(|bytes| u64::try_from(bytes).ok())
            .unwrap_or(u64::MAX);
        limits.check_layout_bytes(layout_bytes)?;
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
            limits.check_segment_alignment(align)?;
            if segment.file_range().offset() % align != segment.vaddr().get() % align {
                return Err(program_header_error(
                    segment.index(),
                    ProgramHeaderField::Alignment,
                    align,
                ));
            }
            let vaddr_range = TargetRange::new(segment.vaddr(), segment.memory_size());
            vaddr_range
                .end()
                .map_err(|error| error.at(LoadStage::Plan))?;
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

        let segment_max_align = segments
            .iter()
            .map(|segment| segment.align)
            .max()
            .unwrap_or(1);
        let profile_align = profile.minimum_image_alignment();
        if !profile_align.is_power_of_two() {
            return Err(LoadError::new(
                LoadStage::Plan,
                LoadErrorKind::InvalidAlignment,
                ErrorContext::Allocation {
                    base: TargetAddr::new(0),
                    len: 0,
                    align: profile_align,
                },
            ));
        }
        let max_align = core::cmp::max(segment_max_align, profile_align);
        let min_vaddr = segments[0].vaddr_range.start();
        let max_vaddr = segments
            .iter()
            .map(|segment| segment.vaddr_range.end())
            .try_fold(TargetAddr::new(0), |current, next| {
                let next = next.map_err(|error| error.at(LoadStage::Plan))?;
                Ok::<_, LoadError>(core::cmp::max(current, next))
            })?;
        let aligned_min_vaddr = min_vaddr
            .align_down(max_align)
            .map_err(|error| error.at(LoadStage::Plan))?;
        let aligned_max_vaddr = max_vaddr
            .align_up(max_align)
            .map_err(|error| error.at(LoadStage::Plan))?;
        let image_span = aligned_max_vaddr
            .checked_sub(aligned_min_vaddr)
            .map_err(|error| error.at(LoadStage::Plan))?;
        limits.check_image_span(image_span)?;

        let entry_vaddr = TargetAddr::new(parsed.header().entry());
        let canonical_entry_vaddr =
            TargetAddr::new(profile.entry_mode().canonical_entry(entry_vaddr.get()));
        let entry_span = profile.entry_mode().minimum_instruction_size();
        let executable = segments.iter().any(|segment| {
            segment.permissions.contains(MemoryPermissions::EXECUTE)
                && segment
                    .vaddr_range
                    .contains_span(canonical_entry_vaddr, entry_span)
        });
        if !executable {
            return Err(LoadError::new(
                LoadStage::Plan,
                LoadErrorKind::PermissionConflict,
                ErrorContext::TargetRange {
                    start: canonical_entry_vaddr,
                    len: entry_span,
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
        if let Some(dynamic) = parsed.dynamic() {
            validate_dynamic_segment(dynamic, &segments)?;
        }

        Ok(ImageLayout {
            aligned_min_vaddr,
            aligned_max_vaddr,
            image_span,
            max_align,
            entry_vaddr,
            canonical_entry_vaddr,
            segments,
            relro: parsed.relro(),
        })
    }
}

impl ImageLoader {
    pub fn plan<R: ElfReader>(
        &self,
        admitted: AdmittedArtifact<R>,
    ) -> LoadResult<PlannedArtifact<R>> {
        self.plan_with_policy(admitted, &Phase0ArtifactPolicy)
    }

    pub fn plan_with_policy<R, P>(
        &self,
        admitted: AdmittedArtifact<R>,
        policy: &P,
    ) -> LoadResult<PlannedArtifact<R>>
    where
        R: ElfReader,
        P: ArtifactFeaturePolicy + ?Sized,
    {
        let parsed = self.inspect(&admitted)?;
        policy
            .validate_program_features(parsed.program_features())
            .map_err(|error| error.with_stage(LoadStage::Plan))?;
        let layout = ImageLayoutBuilder::build(
            &parsed,
            admitted.request().profile(),
            admitted.request().limits(),
        )?;
        Ok(PlannedArtifact {
            artifact: admitted,
            parsed,
            layout,
        })
    }
}

fn validate_dynamic_segment(
    dynamic: crate::DynamicSegmentInfo,
    segments: &[SegmentLayout],
) -> LoadResult<()> {
    if dynamic.file_range().is_empty() || dynamic.file_range().len() > dynamic.memory_size() {
        return Err(program_header_error(
            dynamic.index(),
            ProgramHeaderField::FileRange,
            dynamic.file_range().len(),
        ));
    }

    let segment = segments.iter().find(|segment| {
        segment.permissions().contains(MemoryPermissions::READ)
            && segment
                .vaddr_range()
                .contains_span(dynamic.vaddr(), dynamic.memory_size())
    });
    let Some(segment) = segment else {
        return Err(LoadError::new(
            LoadStage::Plan,
            LoadErrorKind::OutOfBounds,
            ErrorContext::ProgramHeader {
                index: dynamic.index(),
                field: ProgramHeaderField::VirtualRange,
                value: dynamic.vaddr().get(),
            },
        ));
    };
    let offset = dynamic
        .vaddr()
        .checked_sub(segment.vaddr_range().start())
        .map_err(|error| error.at(LoadStage::Plan))?;
    let expected_file_offset = segment.file_range().offset().checked_add(offset);
    let file_end = offset.checked_add(dynamic.file_range().len());
    if expected_file_offset != Some(dynamic.file_range().offset())
        || file_end.is_none_or(|end| end > segment.file_range().len())
    {
        return Err(LoadError::new(
            LoadStage::Plan,
            LoadErrorKind::OutOfBounds,
            ErrorContext::ProgramHeader {
                index: dynamic.index(),
                field: ProgramHeaderField::FileRange,
                value: dynamic.file_range().offset(),
            },
        ));
    }
    Ok(())
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
                field: ProgramHeaderField::Alignment,
                value,
            },
        )),
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
