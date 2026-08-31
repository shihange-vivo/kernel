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
    elf::{DynamicSegmentInfo, LoadSegmentInfo},
    identity::LoadRequest,
    image::{inspect::StackKind, map::LoadedRegion},
    memory::{AllocationOffset, ImageMemory},
    reader::ElfReader,
};

#[derive(Clone, Copy)]
pub(crate) enum RelocationAddend {
    Implicit,
    Explicit(i64),
}

pub(crate) struct RelocationRecord {
    offset: TargetAddress,
    raw_type: u32,
    symbol_index: u32,
    addend: RelocationAddend,
}

impl RelocationRecord {
    #[inline]
    pub const fn new(
        offset: TargetAddress,
        raw_type: u32,
        symbol_index: u32,
        addend: RelocationAddend,
    ) -> Self {
        Self {
            offset,
            raw_type,
            symbol_index,
            addend,
        }
    }

    #[inline]
    pub const fn offset(&self) -> TargetAddress {
        self.offset
    }

    #[inline]
    pub const fn raw_type(&self) -> u32 {
        self.raw_type
    }

    #[inline]
    pub const fn symbol_index(&self) -> u32 {
        self.symbol_index
    }

    #[inline]
    pub const fn addend(&self) -> RelocationAddend {
        self.addend
    }
}

pub(crate) struct DecodedImage<R: ElfReader, M: ImageMemory> {
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
}

impl<R: ElfReader, M: ImageMemory> DecodedImage<R, M> {
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
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RelocationTableKind {
    Rel,
    Rela,
}

#[derive(Default)]
pub(crate) struct RelocationTableTags {
    address: Option<u64>,
    byte_len: Option<u64>,
    entry_size: Option<u64>,
}

impl RelocationTableTags {
    #[inline]
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    #[inline]
    pub fn byte_len(&self) -> Option<u64> {
        self.byte_len
    }

    #[inline]
    pub fn entry_size(&self) -> Option<u64> {
        self.entry_size
    }

    #[inline]
    pub fn address_mut(&mut self) -> &mut Option<u64> {
        &mut self.address
    }

    #[inline]
    pub fn byte_len_mut(&mut self) -> &mut Option<u64> {
        &mut self.byte_len
    }

    #[inline]
    pub fn entry_size_mut(&mut self) -> &mut Option<u64> {
        &mut self.entry_size
    }
}

#[derive(Default)]
pub(crate) struct DynamicTags {
    rel: RelocationTableTags,
    rela: RelocationTableTags,
}

impl DynamicTags {
    #[inline]
    pub fn rel(&self) -> &RelocationTableTags {
        &self.rel
    }

    #[inline]
    pub fn rela(&self) -> &RelocationTableTags {
        &self.rela
    }

    #[inline]
    pub fn rel_mut(&mut self) -> &mut RelocationTableTags {
        &mut self.rel
    }
    #[inline]
    pub fn rela_mut(&mut self) -> &mut RelocationTableTags {
        &mut self.rela
    }
}
