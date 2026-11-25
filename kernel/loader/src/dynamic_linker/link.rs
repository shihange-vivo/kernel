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

//! Map a dependency plan and apply eager relocations in discovery order.

use alloc::vec::Vec;
use goblin::elf::{
    section_header::SHN_UNDEF,
    sym::{STB_LOCAL, STB_WEAK, STV_DEFAULT},
};

use super::{
    exports::ExportBudget,
    reserve,
    scope::{exports_at, LinkScope},
    symbol, DependencyImage, DependencyPlan, ExportedSymbols, LinkedImage, LinkedImages,
};
use crate::{
    elf::{RelocationRecord, SymbolTableReader},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::DecodedImage,
    memory::{ImageMapping, TargetAddress, TargetRange},
    profile::LinkLimits,
    relocation::{relative_value, write::RelocationWrites, SymbolRelocation},
    ElfReader, ImageAllocator, LoadError, LoadResult,
};

/// The new mapping and ELF reader used to preflight symbol relocations.
#[must_use = "keep the decoded image and its corresponding reader together"]
struct RelocationInput<K, R, A: ImageMapping> {
    key: K,
    soname: Option<Vec<u8>>,
    reader: R,
    image: DecodedImage<A>,
    exports: Option<ExportedSymbols>,
}

/// Map and eagerly relocate a discovered dependency graph.
///
/// The allocator supplies disjoint mappings in one target address space. The
/// first matching definition in discovery order wins for default-visibility
/// references. Local and other visibility references bind in their own image.
/// Every relocation is checked before relocation writes begin. On failure the
/// mappings are dropped. Successful images still require cache synchronization
/// and final protection before execution.
pub fn link<K: Eq, R: ElfReader, M: ImageAllocator>(
    plan: DependencyPlan<K, R>,
    limits: LinkLimits,
    allocator: M,
) -> LoadResult<LinkedImages<K, M::Allocation>> {
    link_in_scope(plan, limits, allocator, LinkScope::standalone())
}

pub(super) fn link_in_scope<K: Eq, R: ElfReader, M: ImageAllocator>(
    plan: DependencyPlan<K, R>,
    limits: LinkLimits,
    allocator: M,
    scope: LinkScope<'_, K, M::Allocation>,
) -> LoadResult<LinkedImages<K, M::Allocation>> {
    link_inner(plan, limits, allocator, scope).map_err(|error| error.at_stage(LoadStage::Relocate))
}

fn link_inner<K: Eq, R: ElfReader, M: ImageAllocator>(
    plan: DependencyPlan<K, R>,
    limits: LinkLimits,
    mut allocator: M,
    scope: LinkScope<'_, K, M::Allocation>,
) -> LoadResult<LinkedImages<K, M::Allocation>> {
    let first = scope.existing().len();
    let (images, edges) = plan.into_parts();
    let mut count = 0u64;
    for image in &images {
        count = count
            .checked_add(image.relocation_count()?)
            .ok_or_else(|| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))?;
        limits.check_relocations(count)?;
    }

    let mut mapped = map_dependencies(images, &mut allocator, &scope)?;
    let writes = plan_writes(&mapped, &limits, &scope)?;
    if let Some(export_limits) = limits.export_limits() {
        let budget = ExportBudget::new(export_limits);
        for input in &mut mapped {
            input.exports = Some(ExportedSymbols::build(
                &input.image,
                &input.reader,
                &budget,
                limits.max_symbol_name_len(),
            )?);
        }
    }
    finish_link(mapped, writes).map(|images| LinkedImages::new(images, edges, first))
}

// Keep the large per-image mapping temporaries off the symbol-resolution stack.
#[inline(never)]
fn map_dependencies<K: Eq, R: ElfReader, M: ImageAllocator>(
    images: Vec<DependencyImage<K, R>>,
    allocator: &mut M,
    scope: &LinkScope<'_, K, M::Allocation>,
) -> LoadResult<Vec<RelocationInput<K, R, M::Allocation>>> {
    let mut mapped: Vec<RelocationInput<K, R, M::Allocation>> =
        reserve(images.len()).map_err(|error| error.at_stage(LoadStage::Allocate))?;
    for dependency in images {
        let (key, soname, image) = dependency.into_parts();
        // Forward each owned stage directly and propagate errors after pushing
        // the decoded image, so the loop only unwraps a Result<()>.
        image
            .allocate(&mut *allocator)
            .and_then(|allocated| {
                check_disjoint(
                    allocated.allocation(),
                    mapped.iter().map(|input| input.image.allocation()).chain(
                        scope
                            .existing()
                            .iter()
                            .map(|object| object.image().allocation()),
                    ),
                )?;
                allocated.map_with_reader()
            })
            .and_then(|(image, reader)| {
                image.decode().map(|image| {
                    mapped.push(RelocationInput {
                        key,
                        soname,
                        reader,
                        image,
                        exports: None,
                    });
                })
            })?;
    }
    Ok(mapped)
}

// Keep overlap checking in a separate frame from mapping and decoding.
#[inline(never)]
fn check_disjoint<'a, A: ImageMapping + 'a>(
    allocation: &A,
    mut previous: impl Iterator<Item = &'a A>,
) -> LoadResult<()> {
    let base = allocation.base();
    let len = allocation.len();
    let range = TargetRange::new(base, len);
    if previous.any(|mapping| range.overlaps(TargetRange::new(mapping.base(), mapping.len()))) {
        return Err(LoadError::new(
            LoadErrorKind::IncorrectLayout,
            ErrorContext::Allocation {
                base,
                len,
                align: allocation.align(),
            },
        )
        .at_stage(LoadStage::Allocate));
    }
    Ok(())
}

#[inline(never)]
fn finish_link<K, R: ElfReader, A: ImageMapping>(
    mapped: Vec<RelocationInput<K, R, A>>,
    writes: Vec<RelocationWrites>,
) -> LoadResult<Vec<LinkedImage<K, A>>> {
    let mut images = reserve(mapped.len())?;
    for (input, writes) in mapped.into_iter().zip(writes) {
        input.image.apply_relocation_writes(writes).map(|image| {
            images.push(LinkedImage::new(
                input.key,
                input.soname,
                image,
                input.exports,
            ));
        })?;
    }
    Ok(images)
}

struct SymbolLookup<'a, K, R: ElfReader, A: ImageMapping> {
    inputs: &'a [RelocationInput<K, R, A>],
    tables: Vec<Option<SymbolTableReader<'a, R>>>,
    scope: &'a LinkScope<'a, K, A>,
    limits: &'a LinkLimits,
    probes: u64,
}

fn plan_writes<K: Eq, R: ElfReader, A: ImageMapping>(
    inputs: &[RelocationInput<K, R, A>],
    limits: &LinkLimits,
    scope: &LinkScope<'_, K, A>,
) -> LoadResult<Vec<RelocationWrites>> {
    // Each table borrows the reader at the same index in the inputs.
    let mut tables = reserve(inputs.len())?;
    for input in inputs {
        tables.push(symbol::read_table(&input.image, &input.reader)?);
    }
    SymbolLookup {
        inputs,
        tables,
        scope,
        limits,
        probes: 0,
    }
    .plan()
}

impl<K: Eq, R: ElfReader, A: ImageMapping> SymbolLookup<'_, K, R, A> {
    fn plan(mut self) -> LoadResult<Vec<RelocationWrites>> {
        let mut writes = reserve(self.inputs.len())?;
        for (index, input) in self.inputs.iter().enumerate() {
            let bias = input.image.load_bias();
            let planned = input
                .image
                .plan_relocation_writes(|record| self.resolve(index, record, bias))?;
            writes.push(planned);
        }
        Ok(writes)
    }

    fn resolve(
        &mut self,
        requester: usize,
        record: &RelocationRecord,
        bias: i128,
    ) -> LoadResult<Option<i128>> {
        let image = &self.inputs[requester].image;
        let profile = image.profile();
        let Some(relocation) = profile.check_symbol_relocation(record)? else {
            return relative_value(profile, bias, record);
        };
        let fail = |kind| LoadError::relocation(record, kind);
        let (addend, jump) = match relocation {
            SymbolRelocation::Address(addend) => (addend, false),
            SymbolRelocation::JumpSlot(addend) => (addend, true),
        };
        if record.symbol_index() == 0 {
            return if jump {
                Err(fail(LoadErrorKind::BadElf))
            } else {
                Ok(Some(i128::from(addend)))
            };
        }
        let table = self.tables[requester]
            .as_ref()
            .ok_or_else(|| fail(LoadErrorKind::BadElf))?;
        let symbol = table.read(record.symbol_index())?;
        let existing = self.scope.existing();
        let first = existing.len();
        let definition = if symbol.binding() == STB_LOCAL || symbol.visibility() != STV_DEFAULT {
            symbol::symbol_address(image, &symbol)?.map(|address| (first + requester, address))
        } else {
            profile.check_symbol(&symbol)?;
            let name = table.name(&symbol, self.limits.max_symbol_name_len())?;
            if name.is_empty() {
                return Err(fail(LoadErrorKind::BadElf));
            }
            self.find(&name)?
        };

        let Some((provider, address)) = definition else {
            if symbol.binding() != STB_WEAK || u32::from(symbol.section_index()) != SHN_UNDEF {
                return Err(fail(LoadErrorKind::UnresolvedSymbol));
            }
            // A weak import may resolve to zero. A nonzero PLT result must point to code.
            if jump && addend != 0 {
                return Err(fail(LoadErrorKind::PermissionConflict));
            }
            return Ok(Some(i128::from(addend)));
        };
        let value = i128::from(address.get()) + i128::from(addend);
        if jump {
            let address = u64::try_from(value).map_err(|_| fail(LoadErrorKind::IntegerOverflow))?;
            let mode = profile.entry_mode();
            if !address.is_multiple_of(u64::from(mode.instruction_alignment())) {
                return Err(fail(LoadErrorKind::InvalidAlignment));
            }
            let address = TargetAddress::new(address);
            let len = u64::from(mode.minimum_instruction_size());
            let executable = if provider < first {
                existing[provider]
                    .exports()
                    .is_some_and(|exports| exports.contains_executable_span(address, len))
            } else {
                symbol::contains_executable_span(&self.inputs[provider - first].image, address, len)
            };
            if !executable {
                return Err(fail(LoadErrorKind::PermissionConflict));
            }
        }
        Ok(Some(value))
    }

    fn find(&mut self, name: &[u8]) -> LoadResult<Option<(usize, TargetAddress)>> {
        let existing = self.scope.existing();
        let first = existing.len();
        symbol::find_in_scope(self.scope.indexes(self.inputs.len()), |index| {
            if index < first {
                let exports = exports_at(existing, index)?;
                Self::charge_probe(self.limits, &mut self.probes)?;
                return Ok(exports.find(name));
            }

            let index = index - first;
            let Some(table) = self.tables[index].as_ref() else {
                return Ok(None);
            };
            Self::charge_probe(self.limits, &mut self.probes)?;
            symbol::lookup_export_address(
                &self.inputs[index].image,
                table,
                name,
                self.limits.max_symbol_name_len(),
            )
        })
    }

    fn charge_probe(limits: &LinkLimits, probes: &mut u64) -> LoadResult<()> {
        *probes = probes
            .checked_add(1)
            .ok_or_else(|| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))?;
        limits.check_symbol_lookups(*probes)
    }
}
