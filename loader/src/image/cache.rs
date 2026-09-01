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
    address::{FileRange, TargetAddress, TargetRange},
    cache::CacheSyncOutcome,
    elf::{DynamicSegmentInfo, LoadSegmentInfo},
    error::{LoadResult, LoadStage},
    identity::LoadRequest,
    image::{
        inspect::StackKind,
        map::LoadedRegion,
        seal::{
            AppliedProtectionSet, PreparedProtectionPlan, ProtectionBatch, SealPlan, SealedImage,
        },
        RelocationRecord,
    },
    memory::{ImageMemory, ImageProtectionMemory},
    reader::ElfReader,
};

pub(crate) struct CachedImage<R: ElfReader, M: ImageMemory> {
    reader: R,
    memory: M,
    load_bias: TargetAddress,
    request: LoadRequest,
    entry_vaddr: TargetAddress,
    canonical_entry_vaddr: TargetAddress,
    load_segments: Box<[LoadSegmentInfo]>,
    regions: Vec<LoadedRegion>,
    dynamic: Option<DynamicSegmentInfo>,
    relocations: Vec<RelocationRecord>,
    relro: Option<TargetRange>,
    stack: StackKind,
    interpreter: Option<FileRange>,
    tls: Option<TargetRange>,
    cache_sync: CacheSyncOutcome,
}

impl<R: ElfReader, M: ImageMemory> CachedImage<R, M> {
    #[inline]
    pub fn new(
        reader: R,
        memory: M,
        load_bias: TargetAddress,
        request: LoadRequest,
        entry_vaddr: TargetAddress,
        canonical_entry_vaddr: TargetAddress,
        load_segments: Box<[LoadSegmentInfo]>,
        regions: Vec<LoadedRegion>,
        dynamic: Option<DynamicSegmentInfo>,
        relocations: Vec<RelocationRecord>,
        relro: Option<TargetRange>,
        stack: StackKind,
        interpreter: Option<FileRange>,
        tls: Option<TargetRange>,
        cache_sync: CacheSyncOutcome,
    ) -> Self {
        Self {
            reader,
            memory,
            load_bias,
            request,
            entry_vaddr,
            canonical_entry_vaddr,
            load_segments,
            regions,
            dynamic,
            relocations,
            relro,
            stack,
            interpreter,
            tls,
            cache_sync,
        }
    }

    #[inline]
    pub const fn cache_sync(&self) -> &CacheSyncOutcome {
        &self.cache_sync
    }

    pub fn seal(mut self) -> LoadResult<SealedImage<R, M>>
    where
        M: ImageProtectionMemory,
    {
        let allocation = *self
            .memory
            .allocation()
            .map_err(|error| error.at_stage(LoadStage::Seal))?;
        let seal_plan = SealPlan::build(
            &allocation,
            self.load_bias,
            self.request.profile().class(),
            &self.load_segments,
            &self.regions,
            self.relro,
            &self.stack,
            &self.relocations,
        )?;
        let prepared = PreparedProtectionPlan::prepare(&self.memory, &allocation, &seal_plan)?;
        let mut protection_records = prepared.into_ranges();
        self.memory
            .apply_protection(ProtectionBatch::new(&mut protection_records))
            .map_err(|error| error.at_stage(LoadStage::Seal))?;
        let protections = AppliedProtectionSet::new(protection_records);

        Ok(SealedImage::new(
            self.reader,
            self.memory,
            self.load_bias,
            self.request,
            self.entry_vaddr,
            self.canonical_entry_vaddr,
            self.load_segments,
            self.regions,
            self.dynamic,
            self.relocations,
            self.relro,
            self.stack,
            self.interpreter,
            self.tls,
            self.cache_sync,
            seal_plan,
            protections,
        ))
    }
}
