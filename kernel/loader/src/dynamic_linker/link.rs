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
    exports::ExportBudget, reserve, symbol, DependencyEdge, DependencyPlan, ExportedSymbols,
    LinkedLifecycle,
};
use crate::{
    elf::{RelocationRecord, SymbolTableReader},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::{DecodedImage, RelocatedImage},
    memory::{ImageMapping, TargetAddress, TargetRange},
    profile::LinkLimits,
    relocation::{relative_value, write::RelocationWrites, SymbolRelocation},
    CodeCache, ElfReader, ImageAllocator, LoadError, LoadResult, LoadedImages, LoadedObject,
};

/// One relocated ELF and its backing, retained by the dependency closure.
#[must_use = "retain the linked image to keep its mapping alive"]
pub struct LinkedImage<K, A: ImageMapping> {
    key: K,
    soname: Option<Vec<u8>>,
    image: RelocatedImage<A>,
    exports: Option<ExportedSymbols>,
}

impl<K, A: ImageMapping> LinkedImage<K, A> {
    pub const fn key(&self) -> &K {
        &self.key
    }

    pub fn soname(&self) -> Option<&[u8]> {
        self.soname.as_deref()
    }

    /// Inspect relocated data while keeping the owning result alive.
    pub const fn allocation(&self) -> &A {
        self.image.allocation()
    }

    /// Runtime address of the entry. Execution requires image finalization.
    pub const fn entry(&self) -> Option<TargetAddress> {
        self.image.entry()
    }
}

/// All relocated images in a dependency graph, with their mappings retained.
#[must_use = "retain the linked images to keep all provider mappings alive"]
pub struct LinkedImages<K, A: ImageMapping> {
    images: Vec<LinkedImage<K, A>>,
    edges: Vec<DependencyEdge>,
}

impl<K, A: ImageMapping> LinkedImages<K, A> {
    /// The root and its dependencies in breadth-first order.
    pub fn images(&self) -> &[LinkedImage<K, A>] {
        &self.images
    }

    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }

    /// Read the relocated callbacks and order them by dependency. Keep this
    /// group alive for as long as the returned target addresses are in use.
    pub fn plan_lifecycle(&self) -> LoadResult<LinkedLifecycle> {
        self.plan_lifecycle_inner()
            .map_err(|error| error.at_stage(LoadStage::Lifecycle))
    }

    fn plan_lifecycle_inner(&self) -> LoadResult<LinkedLifecycle> {
        let mut plans = reserve(self.images.len())?;
        for linked in &self.images {
            plans.push(linked.image.lifecycle()?);
        }
        LinkedLifecycle::build(&self.edges, plans)
    }

    /// Finalize the graph and transfer all mappings into one owning result.
    /// Lifecycle validation covers the whole graph before publishing code or
    /// tightening RELRO. On error every mapping is dropped.
    pub fn seal<C: CodeCache + ?Sized>(self, cache: &mut C) -> LoadResult<LoadedImages<K, A>> {
        let (plans, init_order) = self.plan_lifecycle()?.into_parts();
        let mut images =
            reserve(self.images.len()).map_err(|error| error.at_stage(LoadStage::Seal))?;
        for (linked, lifecycle) in self.images.into_iter().zip(plans) {
            let image = linked.image.seal_with_lifecycle(cache, lifecycle)?;
            images.push(LoadedObject::new(
                linked.key,
                linked.soname,
                image,
                linked.exports,
            ));
        }
        Ok(LoadedImages::new(images, self.edges, init_order))
    }
}

#[must_use = "keep the decoded image and its corresponding reader together"]
struct LinkInput<K, R, A: ImageMapping> {
    key: K,
    soname: Option<Vec<u8>>,
    reader: R,
    image: DecodedImage<A>,
}

/// Map and eagerly relocate a discovered dependency graph.
///
/// The allocator supplies disjoint mappings in one target address space. The
/// first matching definition in discovery order wins for default-visibility
/// references. Local and other visibility references bind in their own image.
/// Every relocation is checked before relocation writes begin. On failure the
/// mappings are dropped. Successful images still require cache synchronization
/// and final protection before execution.
pub fn link<K, R: ElfReader, M: ImageAllocator>(
    plan: DependencyPlan<K, R>,
    limits: LinkLimits,
    allocator: M,
) -> LoadResult<LinkedImages<K, M::Allocation>> {
    link_inner(plan, limits, allocator).map_err(|error| error.at_stage(LoadStage::Relocate))
}

fn link_inner<K, R: ElfReader, M: ImageAllocator>(
    plan: DependencyPlan<K, R>,
    limits: LinkLimits,
    mut allocator: M,
) -> LoadResult<LinkedImages<K, M::Allocation>> {
    let (images, edges) = plan.into_parts();
    let mut count = 0u64;
    for image in &images {
        count = count
            .checked_add(image.relocation_count()?)
            .ok_or_else(|| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))?;
        limits.check_relocations(count)?;
    }

    let mut mapped: Vec<LinkInput<K, R, M::Allocation>> =
        reserve(images.len()).map_err(|error| error.at_stage(LoadStage::Allocate))?;
    for dependency in images {
        let (key, soname, image) = dependency.into_parts();
        let allocated = image.allocate(&mut allocator)?;
        let allocation = allocated.allocation();
        let range = TargetRange::new(allocation.base(), allocation.len());
        if mapped.iter().any(|previous| {
            let previous = previous.image.allocation();
            range.overlaps(TargetRange::new(previous.base(), previous.len()))
        }) {
            return Err(LoadError::new(
                LoadErrorKind::IncorrectLayout,
                ErrorContext::Allocation {
                    base: allocation.base(),
                    len: allocation.len(),
                    align: allocation.align(),
                },
            )
            .at_stage(LoadStage::Allocate));
        }
        let (image, reader) = allocated.map_with_reader()?;
        mapped.push(LinkInput {
            key,
            soname,
            reader,
            image: image.decode()?,
        });
    }

    let writes = plan_writes(&mapped, &limits)?;
    let mut exports = Vec::new();
    if let Some(export_limits) = limits.export_limits() {
        let budget = ExportBudget::new(export_limits);
        exports = reserve(mapped.len())?;
        for input in &mapped {
            exports.push(ExportedSymbols::build(
                &input.image,
                &input.reader,
                &budget,
                limits.max_symbol_name_len(),
            )?);
        }
    }
    let mut exports = exports.into_iter();
    let mut images = reserve(mapped.len())?;
    for (input, writes) in mapped.into_iter().zip(writes) {
        images.push(LinkedImage {
            key: input.key,
            soname: input.soname,
            image: input.image.apply_relocation_writes(writes)?,
            exports: exports.next(),
        });
    }
    Ok(LinkedImages { images, edges })
}

fn plan_writes<K, R: ElfReader, A: ImageMapping>(
    inputs: &[LinkInput<K, R, A>],
    limits: &LinkLimits,
) -> LoadResult<Vec<RelocationWrites>> {
    // Symbol lookups borrow each stable ELF reader during the relocation preflight.
    let mut tables = reserve(inputs.len())?;
    for input in inputs {
        tables.push(symbol::read_table(&input.image, &input.reader)?);
    }
    let mut writes = reserve(inputs.len())?;
    let mut lookups = 0;
    for (index, input) in inputs.iter().enumerate() {
        let bias = input.image.load_bias();
        writes.push(input.image.plan_relocation_writes(|record| {
            resolve_relocation(inputs, &tables, index, record, bias, limits, &mut lookups)
        })?);
    }
    Ok(writes)
}

fn resolve_relocation<K, R: ElfReader, A: ImageMapping>(
    inputs: &[LinkInput<K, R, A>],
    tables: &[Option<SymbolTableReader<'_, R>>],
    requester: usize,
    record: &RelocationRecord,
    bias: i128,
    limits: &LinkLimits,
    lookups: &mut u64,
) -> LoadResult<Option<i128>> {
    let image = &inputs[requester].image;
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
    let table = tables[requester]
        .as_ref()
        .ok_or_else(|| fail(LoadErrorKind::BadElf))?;
    let symbol = table.read(record.symbol_index())?;
    let definition = if symbol.binding() == STB_LOCAL || symbol.visibility() != STV_DEFAULT {
        symbol::symbol_address(image, &symbol)?.map(|address| (image, address))
    } else {
        profile.check_symbol(&symbol)?;
        let name = table.name(&symbol, limits.max_symbol_name_len())?;
        if name.is_empty() {
            return Err(fail(LoadErrorKind::BadElf));
        }
        lookup(inputs, tables, &name, limits, lookups)?
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
        if !symbol::contains_executable_span(
            provider,
            TargetAddress::new(address),
            u64::from(mode.minimum_instruction_size()),
        ) {
            return Err(fail(LoadErrorKind::PermissionConflict));
        }
    }
    Ok(Some(value))
}

fn lookup<'a, K, R: ElfReader, A: ImageMapping>(
    inputs: &'a [LinkInput<K, R, A>],
    tables: &[Option<SymbolTableReader<'_, R>>],
    name: &[u8],
    limits: &LinkLimits,
    lookups: &mut u64,
) -> LoadResult<Option<(&'a DecodedImage<A>, TargetAddress)>> {
    for (input, table) in inputs.iter().zip(tables) {
        let Some(table) = table else { continue };
        *lookups = lookups
            .checked_add(1)
            .ok_or_else(|| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))?;
        limits.check_symbol_lookups(*lookups)?;
        if let Some(symbol) = symbol::lookup_export(table, name, limits.max_symbol_name_len())?
            && let Some(address) = symbol::symbol_address(&input.image, &symbol)?
        {
            return Ok(Some((&input.image, address)));
        }
    }
    Ok(None)
}
