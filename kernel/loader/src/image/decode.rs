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

//! Decoded image metadata retained for relocation and linking.

use alloc::vec::Vec;
use goblin::elf::{
    section_header::{SHN_ABS, SHN_UNDEF},
    sym::STT_FUNC,
};

use super::relocate::RelocatedImage;
use crate::{
    elf::{DynamicInfo, LoadSegmentInfo, RelocationRecord, SymbolRecord},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    memory::{ImageMapping, MemoryPermissions, TargetAddress, TargetRange},
    profile::LoadProfile,
    relocation, LoadError, LoadResult, ProgramHeaderTable,
};

#[must_use = "retain the decoded image to keep its allocation alive"]
pub(crate) struct DecodedImage<A: ImageMapping> {
    pub(super) program_headers: Option<ProgramHeaderTable>,
    pub(super) allocation: A,
    pub(super) profile: LoadProfile,
    pub(super) segments: Vec<LoadSegmentInfo>,
    pub(super) relro: Option<TargetRange>,
    pub(super) image_start: TargetAddress,
    pub(super) entry: Option<TargetAddress>,
    pub(super) dynamic: Option<DynamicInfo>,
    pub(super) relocations: Vec<RelocationRecord>,
}

impl<A: ImageMapping> DecodedImage<A> {
    /// Resolve a record from this image's own symbol table.
    /// The image must remain alive while a mapped address is used. An absolute
    /// value is returned as-is and carries no guarantee about its backing.
    pub(crate) fn symbol_address(
        &self,
        symbol: &SymbolRecord,
    ) -> LoadResult<Option<TargetAddress>> {
        self.profile.check_symbol(symbol)?;
        let address = TargetAddress::new(symbol.value());
        match u32::from(symbol.section_index()) {
            SHN_UNDEF => return Ok(None),
            SHN_ABS => return Ok(Some(address)),
            _ => {}
        }

        // A zero size gives no extent. The address itself must still be mapped.
        let len = symbol.size().max(1);
        address.checked_add(len)?;
        let context = || ErrorContext::TargetRange {
            start: address,
            len,
            align: 1,
        };
        let segment = self
            .segments
            .iter()
            .find(|segment| {
                TargetRange::new(segment.vaddr(), segment.memory_size()).contains_span(address, len)
            })
            .ok_or_else(|| LoadError::new(LoadErrorKind::OutOfBounds, context()))?;
        let required = if symbol.kind() == STT_FUNC {
            MemoryPermissions::EXECUTE
        } else {
            MemoryPermissions::READ
        };
        if !segment.permissions().contains(required) {
            return Err(LoadError::new(LoadErrorKind::PermissionConflict, context()));
        }

        let offset = address.checked_sub(self.image_start)?;
        Ok(Some(self.allocation.base().checked_add(offset)?))
    }

    pub(crate) fn relocate(self) -> LoadResult<RelocatedImage<A>> {
        self.relocate_inner()
            .map_err(|error| error.at_stage(LoadStage::Relocate))
    }

    fn relocate_inner(mut self) -> LoadResult<RelocatedImage<A>> {
        relocation::apply_relative(
            &mut self.allocation,
            &self.profile,
            &self.segments,
            self.image_start,
            &self.relocations,
        )?;
        Ok(RelocatedImage {
            program_headers: self.program_headers,
            allocation: self.allocation,
            profile: self.profile,
            segments: self.segments,
            relro: self.relro,
            image_start: self.image_start,
            entry: self.entry,
            dynamic: self.dynamic,
        })
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
