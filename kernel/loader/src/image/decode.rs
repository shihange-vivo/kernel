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

//! Decoded relocation records and their image backing.

use alloc::vec::Vec;

use super::relocate::RelocatedImage;
use crate::{
    elf::{DynamicInfo, LoadSegmentInfo, RelocationRecord},
    error::LoadStage,
    memory::{ImageMapping, TargetAddress, TargetRange},
    profile::LoadProfile,
    relocation::{
        relative_value,
        write::{self, RelocationWrites},
    },
    LoadResult, ProgramHeaderTable,
};

#[must_use = "retain the decoded image to keep its allocation alive"]
pub(crate) struct DecodedImage<A: ImageMapping> {
    program_headers: Option<ProgramHeaderTable>,
    allocation: A,
    profile: LoadProfile,
    segments: Vec<LoadSegmentInfo>,
    relro: Option<TargetRange>,
    image_start: TargetAddress,
    entry: Option<TargetAddress>,
    dynamic: Option<DynamicInfo>,
    relocations: Vec<RelocationRecord>,
}

impl<A: ImageMapping> DecodedImage<A> {
    pub(super) const fn new(
        program_headers: Option<ProgramHeaderTable>,
        allocation: A,
        profile: LoadProfile,
        segments: Vec<LoadSegmentInfo>,
        relro: Option<TargetRange>,
        image_start: TargetAddress,
        entry: Option<TargetAddress>,
        dynamic: Option<DynamicInfo>,
        relocations: Vec<RelocationRecord>,
    ) -> Self {
        Self {
            program_headers,
            allocation,
            profile,
            segments,
            relro,
            image_start,
            entry,
            dynamic,
            relocations,
        }
    }

    /// Relocate a self-contained image through the standalone profile.
    pub(crate) fn relocate(self) -> LoadResult<RelocatedImage<A>> {
        let bias = self.load_bias();
        self.plan_relocation_writes(|record| relative_value(&self.profile, bias, record))
            .and_then(|writes| self.apply_relocation_writes(writes))
            .map_err(|error| error.at_stage(LoadStage::Relocate))
    }

    /// Validate and encode the writes without modifying this mapping.
    pub(crate) fn plan_relocation_writes(
        &self,
        resolve: impl FnMut(&RelocationRecord) -> LoadResult<Option<i128>>,
    ) -> LoadResult<RelocationWrites> {
        write::plan(
            &self.allocation,
            self.profile.class(),
            self.profile.endian(),
            &self.segments,
            self.image_start,
            &self.relocations,
            resolve,
        )
    }

    /// Apply this image's validated writes and advance to the relocated stage.
    pub(crate) fn apply_relocation_writes(
        mut self,
        writes: RelocationWrites,
    ) -> LoadResult<RelocatedImage<A>> {
        writes.apply(&mut self.allocation)?;
        Ok(RelocatedImage::new(
            self.program_headers,
            self.allocation,
            self.profile,
            self.segments,
            self.relro,
            self.image_start,
            self.entry,
            self.dynamic,
        ))
    }

    pub(crate) const fn profile(&self) -> &LoadProfile {
        &self.profile
    }

    pub(crate) fn segments(&self) -> &[LoadSegmentInfo] {
        &self.segments
    }

    pub(crate) const fn image_start(&self) -> TargetAddress {
        self.image_start
    }

    pub(crate) fn load_bias(&self) -> i128 {
        i128::from(self.allocation.base().get()) - i128::from(self.image_start.get())
    }

    pub(crate) const fn allocation(&self) -> &A {
        &self.allocation
    }
    pub(crate) const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }
    pub(crate) fn dynamic(&self) -> Option<&DynamicInfo> {
        self.dynamic.as_ref()
    }
    pub(crate) fn relocations(&self) -> &[RelocationRecord] {
        &self.relocations
    }
}
