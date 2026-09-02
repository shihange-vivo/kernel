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
    error::{ErrorContext, HeaderField, LoadError, LoadErrorKind, LoadResult, LoadStage},
    identity::LoadRequest,
    image::{inspect::StackKind, map::LoadedRegion, relocate::RelocatedImage},
    memory::{AllocationOffset, ImageAllocation, ImageLoadTransaction, ImageMemory},
    reader::ElfReader,
    relocation::{AddendEncoding, ArchRelocator, RelocationOperation, TargetWord, WordWidth},
};

#[derive(Clone, Copy)]
pub(crate) enum RelocationAddend {
    Implicit,
    Explicit(i64),
}

#[derive(Clone, Copy)]
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

#[must_use = "dropping a decoded image aborts its allocation"]
pub(crate) struct DecodedImage<R: ElfReader, M: ImageMemory> {
    reader: R,
    transaction: ImageLoadTransaction<M>,
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
        transaction: ImageLoadTransaction<M>,
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
            transaction,
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

    fn validate_relocator<A: ArchRelocator>(&self, relocator: &A) -> LoadResult<()> {
        let profile = self.request.profile();
        if relocator.machine() == profile.machine() && relocator.class() == profile.class() {
            Ok(())
        } else {
            let (field, value) = if relocator.machine() != profile.machine() {
                (HeaderField::Machine, u64::from(relocator.machine()))
            } else {
                (HeaderField::Class, u64::from(relocator.class()))
            };
            Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::HeaderField { field, value },
            ))
        }
    }

    fn locate_vaddr_at(&self, vaddr: TargetAddress, len: u64) -> LoadResult<AllocationOffset> {
        let region = self
            .regions
            .iter()
            .find(|region| region.vaddr_range().contains_span(vaddr, len))
            .ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange {
                        start: vaddr,
                        len,
                        align: 0,
                    },
                )
            })?;
        let offset = vaddr.checked_sub(region.vaddr_range().start())?;
        region.allocation_offset().checked_add(offset)
    }

    fn preflight_relative<A: ArchRelocator>(
        &self,
        record: RelocationRecord,
        relocator: &A,
        target_word: TargetWord,
    ) -> LoadResult<RelocationOperation> {
        if record.raw_type() != relocator.relative_type() || record.symbol_index() != 0 {
            return Err(relocation_error(
                record,
                LoadErrorKind::UnsupportedByProfile,
            ));
        }
        let addend = match (relocator.addend_encoding(), record.addend()) {
            (AddendEncoding::Explicit, RelocationAddend::Explicit(value)) => i128::from(value),
            (AddendEncoding::Implicit, RelocationAddend::Implicit) => {
                let offset = self
                    .locate_vaddr_at(record.offset(), target_word.width().bytes())
                    .map_err(|_| relocation_error(record, LoadErrorKind::OutOfBounds))?;
                i128::from(target_word.read_via(&self.transaction, offset)?)
            }
            _ => {
                return Err(relocation_error(
                    record,
                    LoadErrorKind::UnsupportedByProfile,
                ))
            }
        };
        let offset = self
            .locate_vaddr_at(record.offset(), target_word.width().bytes())
            .map_err(|_| relocation_error(record, LoadErrorKind::OutOfBounds))?;
        let result = i128::from(self.load_bias.get())
            .checked_add(addend)
            .filter(|value| *value >= 0 && *value <= i128::from(target_word.width().maximum()))
            .ok_or_else(|| relocation_error(record, LoadErrorKind::IntegerOverflow))?;
        let value = result as u64;
        Ok(RelocationOperation::new(offset, value, record))
    }

    pub fn relocation<A: ArchRelocator>(
        mut self,
        relocator: A,
    ) -> LoadResult<RelocatedImage<R, M>> {
        self.validate_relocator(&relocator)
            .map_err(|error| error.at_stage(LoadStage::Relocate))?;
        let target_word = TargetWord::new(
            WordWidth::for_elf_class(self.request.profile().class()),
            self.request.profile().endian(),
        );
        let mut operations = Vec::new();
        let operation_bytes = self
            .relocations
            .len()
            .checked_mul(core::mem::size_of::<RelocationOperation>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .unwrap_or(u64::MAX);
        self.request
            .limits()
            .check_relocation_operation_bytes(operation_bytes)
            .map_err(|error| error.at_stage(LoadStage::Relocate))?;
        operations
            .try_reserve_exact(self.relocations.len())
            .map_err(|_| {
                LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
                    .at_stage(LoadStage::Relocate)
            })?;

        for record in self.relocations.iter() {
            operations.push(
                self.preflight_relative(*record, &relocator, target_word)
                    .map_err(|error| error.at_stage(LoadStage::Relocate))?,
            );
        }
        operations.sort_unstable_by_key(|operation| operation.offset().value());
        for pair in operations.windows(2) {
            let end = pair[0]
                .offset()
                .checked_add(target_word.width().bytes())
                .map_err(|_| {
                    relocation_error(pair[0].record(), LoadErrorKind::IntegerOverflow)
                        .at_stage(LoadStage::Relocate)
                })?;
            if pair[1].offset() < end {
                return Err(relocation_error(pair[1].record(), LoadErrorKind::BadElf)
                    .at_stage(LoadStage::Relocate));
            }
        }
        for operation in operations {
            target_word
                .write_via(&mut self.transaction, operation.offset(), operation.value())
                .map_err(|error| error.at_stage(LoadStage::Relocate))?;
        }
        Ok(RelocatedImage::new(
            self.reader,
            self.transaction,
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
        ))
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

fn relocation_error(record: RelocationRecord, kind: LoadErrorKind) -> LoadError {
    LoadError::new(
        kind,
        ErrorContext::Relocation {
            offset: record.offset(),
            raw_type: record.raw_type(),
            symbol_index: record.symbol_index(),
        },
    )
}
