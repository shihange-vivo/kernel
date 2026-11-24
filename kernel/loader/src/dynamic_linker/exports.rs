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

//! Optional owned export indexes for finalized images.

use alloc::vec::Vec;
use core::cell::Cell;

use super::{reserve, symbol};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    image::DecodedImage,
    memory::{ImageMapping, TargetAddress},
    profile::ExportLimits,
    ElfReader, LoadError, LoadResult,
};

#[derive(Debug)]
struct Export {
    name: Vec<u8>,
    address: TargetAddress,
}

/// Validated runtime addresses indexed by their raw ELF names.
///
/// Addresses are usable only while the owning image graph is retained in its
/// original target address space.
#[derive(Debug, Default)]
pub struct ExportedSymbols {
    entries: Vec<Export>,
}

impl ExportedSymbols {
    pub fn find(&self, name: &[u8]) -> Option<TargetAddress> {
        let index = self
            .entries
            .binary_search_by(|entry| entry.name.as_slice().cmp(name));
        index.ok().map(|index| self.entries[index].address)
    }

    pub(super) fn build(
        image: &DecodedImage<impl ImageMapping>,
        reader: &impl ElfReader,
        budget: &ExportBudget,
        max_name_len: u32,
    ) -> LoadResult<Self> {
        let reader = ExportReader { reader, budget };
        let Some(table) = symbol::read_table(image, &reader)? else {
            return Ok(Self::default());
        };
        let mut names = Vec::new();
        for index in 1..table.count() {
            let record = table.read(index)?;
            if symbol::is_export(&record) {
                let name = table.name(&record, max_name_len)?;
                if name.is_empty() {
                    continue;
                }
                budget.charge_name(name.len())?;
                names
                    .try_reserve(1)
                    .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
                names.push(name);
            }
        }
        names.sort_unstable();
        names.dedup();

        let mut entries = reserve(names.len())?;
        // Resolve each name through the selected ELF hash so the retained index
        // preserves the same first match and GNU hash exclusions as linking.
        for name in names {
            if let Some(record) = symbol::lookup_export(&table, &name, max_name_len)?
                && let Some(address) = symbol::symbol_address(image, &record)?
            {
                entries.push(Export { name, address });
            }
        }
        Ok(Self { entries })
    }
}

pub(super) struct ExportBudget {
    limits: ExportLimits,
    reads: Cell<u64>,
    name_bytes: Cell<u64>,
}

impl ExportBudget {
    pub(super) fn new(limits: ExportLimits) -> Self {
        Self {
            limits,
            reads: Cell::new(0),
            name_bytes: Cell::new(0),
        }
    }

    fn charge_name(&self, len: usize) -> LoadResult<()> {
        let bytes = self
            .name_bytes
            .get()
            .checked_add(len as u64)
            .ok_or_else(overflow)?;
        self.limits.check_name_bytes(bytes)?;
        self.name_bytes.set(bytes);
        Ok(())
    }
}

struct ExportReader<'a, R> {
    reader: &'a R,
    budget: &'a ExportBudget,
}

impl<R: ElfReader> ElfReader for ExportReader<'_, R> {
    fn len(&self) -> LoadResult<u64> {
        self.reader.len()
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let reads = self
            .budget
            .reads
            .get()
            .checked_add(1)
            .ok_or_else(overflow)?;
        self.budget.limits.check_reads(reads)?;
        self.budget.reads.set(reads);
        self.reader.read_exact_at(offset, dst)
    }
}

fn overflow() -> LoadError {
    LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None)
}
