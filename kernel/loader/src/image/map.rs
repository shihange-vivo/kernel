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

//! Initialized, segment-protected images and runtime metadata decoding.
//! Relocation, cache synchronization and RELRO protection follow later.

use super::decode::DecodedImage;
use crate::{
    cache::publish_segments,
    elf::{DynamicInfo, LoadSegmentInfo, RelocationRecord},
    error::{ErrorContext, LimitKind, LoadErrorKind, LoadStage},
    memory::{AllocationOffset, ImageMapping, TargetAddress, TargetRange},
    profile::LoadProfile,
    CodeCache, LoadError, LoadResult, ProgramHeaderTable,
};
use alloc::{ffi::CString, vec::Vec};

/// An ELF mapped for an external interpreter. The interpreter owns dynamic
/// relocations, TLS, relocatable callbacks and RELRO sealing.
#[must_use = "keep the image alive while its entry or data is in use"]
pub struct InterpreterImage<A: ImageMapping> {
    allocation: A,
    entry: TargetAddress,
    program_headers: Option<ProgramHeaderTable>,
    load_bias: u64,
    interpreter: Option<CString>,
}

impl<A: ImageMapping> InterpreterImage<A> {
    pub const fn allocation(&self) -> &A {
        &self.allocation
    }

    pub fn allocation_mut(&mut self) -> &mut A {
        &mut self.allocation
    }

    pub const fn entry(&self) -> TargetAddress {
        self.entry
    }

    pub const fn program_headers(&self) -> Option<ProgramHeaderTable> {
        self.program_headers
    }

    pub const fn load_bias(&self) -> u64 {
        self.load_bias
    }

    pub fn interpreter(&self) -> Option<&core::ffi::CStr> {
        self.interpreter.as_deref()
    }
}

#[must_use = "keep the mapped image alive to retain its backing"]
pub(crate) struct MappedImage<A: ImageMapping> {
    program_headers: Option<ProgramHeaderTable>,
    allocation: A,
    profile: LoadProfile,
    segments: Vec<LoadSegmentInfo>,
    dynamic: Option<DynamicInfo>,
    /// Original ELF virtual range, retained for protection after relocation.
    relro: Option<TargetRange>,
    image_start: TargetAddress,
    entry: Option<TargetAddress>,
}

impl<A: ImageMapping> MappedImage<A> {
    pub(super) const fn new(
        program_headers: Option<ProgramHeaderTable>,
        allocation: A,
        profile: LoadProfile,
        segments: Vec<LoadSegmentInfo>,
        dynamic: Option<DynamicInfo>,
        relro: Option<TargetRange>,
        image_start: TargetAddress,
        entry: Option<TargetAddress>,
    ) -> Self {
        Self {
            program_headers,
            allocation,
            profile,
            segments,
            dynamic,
            relro,
            image_start,
            entry,
        }
    }

    pub(crate) const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    /// Signed displacement, including allocations below the ELF's link address.
    pub(crate) fn load_bias(&self) -> i128 {
        i128::from(self.allocation.base().get()) - i128::from(self.image_start.get())
    }

    pub(crate) fn read(&self, offset: AllocationOffset, dst: &mut [u8]) -> LoadResult<()> {
        self.allocation.read(offset, dst)
    }

    pub(crate) fn hand_off<C: CodeCache + ?Sized>(
        self,
        interpreter: Option<CString>,
        cache: &mut C,
    ) -> LoadResult<InterpreterImage<A>> {
        let base = self.allocation.base();
        self.profile
            .check_protection_level(self.allocation.protection_level())?;
        publish_segments(cache, &self.segments, base, self.image_start)
            .map_err(|error| error.at_stage(LoadStage::Seal))?;
        let entry = self
            .entry
            .ok_or_else(|| LoadError::new(LoadErrorKind::BadElf, ErrorContext::None))?;
        Ok(InterpreterImage {
            load_bias: base.get().wrapping_sub(self.image_start.get()),
            allocation: self.allocation,
            program_headers: self.program_headers,
            entry,
            interpreter,
        })
    }

    pub(crate) fn decode(self) -> LoadResult<DecodedImage<A>> {
        self.decode_inner()
            .map_err(|error| error.at_stage(LoadStage::Decode))
    }

    fn decode_inner(self) -> LoadResult<DecodedImage<A>> {
        let mut relocations = Vec::new();
        if let Some(dynamic) = &self.dynamic {
            let class = self.profile.class();
            let total = dynamic.relocation_count(class)?;
            let capacity = usize::try_from(total).map_err(|_| {
                LoadError::new(
                    LoadErrorKind::ResourceLimit,
                    ErrorContext::Limit {
                        resource: LimitKind::RelocationCount,
                        actual: total,
                        maximum: usize::MAX as u64,
                    },
                )
            })?;
            relocations
                .try_reserve_exact(capacity)
                .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
            let mut raw = [0; 24];
            for table in dynamic.relocation_tables() {
                let range = table.range();
                if range.is_empty() {
                    continue;
                }
                let format = table.format();
                let size = format.entry_size(class);
                let offset = AllocationOffset::new(range.start().checked_sub(self.image_start)?);
                for index in 0..range.len() / size {
                    self.allocation
                        .read(offset.checked_add(index * size)?, &mut raw[..size as usize])?;
                    relocations.push(RelocationRecord::decode(
                        &raw[..size as usize],
                        class,
                        self.profile.endian(),
                        format,
                    )?);
                }
            }
        }
        Ok(DecodedImage::new(
            self.program_headers,
            self.allocation,
            self.profile,
            self.segments,
            self.relro,
            self.image_start,
            self.entry,
            self.dynamic,
            relocations,
        ))
    }
}
