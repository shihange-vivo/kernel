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

//! Discover dependencies and retain each validated ELF reader for linking.

use alloc::vec::Vec;
use goblin::elf::dynamic::{DT_NEEDED, DT_SONAME, DT_STRTAB};

use crate::{
    elf::{strings::read_string, DynamicInfo, FileRange},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::{ImageLoader, PlannedImage},
    profile::{DependencyLimits, LoadPurpose},
    ElfReader, LoadError, LoadRequest, LoadResult,
};

/// Host selection of stable ELF sources for one dependency graph.
pub trait DependencyResolver {
    /// Equal keys identify the same input and dependency search context.
    type Key: Eq;
    /// The contents and length must remain stable through discovery and mapping.
    type Reader: ElfReader;

    /// Resolve one raw DT_NEEDED name in the requester's search context.
    fn resolve(&mut self, requester: &Self::Key, name: &[u8]) -> LoadResult<Self::Key>;

    /// Open a source. Each distinct key, including the root, is opened once.
    fn open(&mut self, key: &Self::Key) -> LoadResult<Self::Reader>;
}

/// An admitted image and its reader retained for mapping.
#[must_use = "retain the dependency image to keep its reader alive"]
pub struct DependencyImage<K, R: ElfReader> {
    key: K,
    depth: u32,
    soname: Option<Vec<u8>>,
    image: PlannedImage<R>,
}

impl<K, R: ElfReader> DependencyImage<K, R> {
    pub(super) fn relocation_count(&self) -> LoadResult<u64> {
        match self.image.dynamic() {
            Some(dynamic) => dynamic.relocation_count(self.image.profile().class()),
            None => Ok(0),
        }
    }

    pub(super) fn into_parts(self) -> (K, Option<Vec<u8>>, PlannedImage<R>) {
        (self.key, self.soname, self.image)
    }

    pub const fn key(&self) -> &K {
        &self.key
    }

    /// Shortest distance from the root in dependency edges.
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Declared DT_SONAME, if present, as raw bytes.
    pub fn soname(&self) -> Option<&[u8]> {
        self.soname.as_deref()
    }
}

/// One DT_NEEDED occurrence and the image indexes it connects.
#[derive(Debug)]
pub struct DependencyEdge {
    requester: usize,
    provider: usize,
    name: Vec<u8>,
}

impl DependencyEdge {
    pub const fn requester(&self) -> usize {
        self.requester
    }

    pub const fn provider(&self) -> usize {
        self.provider
    }

    /// The DT_NEEDED name passed to the resolver.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
}

/// A validated graph and its ELF readers, ready for subsequent mapping.
#[must_use = "dropping the dependency plan releases its ELF readers"]
pub struct DependencyPlan<K, R: ElfReader> {
    images: Vec<DependencyImage<K, R>>,
    edges: Vec<DependencyEdge>,
}

impl<K, R: ElfReader> DependencyPlan<K, R> {
    pub(super) fn into_parts(self) -> (Vec<DependencyImage<K, R>>, Vec<DependencyEdge>) {
        (self.images, self.edges)
    }

    /// Breadth-first discovery order, starting with the root at index zero.
    pub fn images(&self) -> &[DependencyImage<K, R>] {
        &self.images
    }

    /// Edges follow image discovery order and each requester's DT_NEEDED order.
    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }
}

/// Validate the root and every transitively needed image without mapping them.
/// The request sets the root's purpose. Providers are admitted as shared objects.
/// The resolver sees every DT_NEEDED occurrence, even when a key is already known.
/// Success retains all readers in the plan. Failure drops all opened readers.
pub fn discover<D: DependencyResolver>(
    root: D::Key,
    request: LoadRequest,
    limits: DependencyLimits,
    resolver: &mut D,
) -> LoadResult<DependencyPlan<D::Key, D::Reader>> {
    discover_with_existing(root, request, limits, resolver, 0, 0, |_| None)
}

pub(super) fn discover_with_existing<D: DependencyResolver>(
    root: D::Key,
    request: LoadRequest,
    limits: DependencyLimits,
    resolver: &mut D,
    first: usize,
    existing_edges: usize,
    find_existing: impl Fn(&D::Key) -> Option<usize>,
) -> LoadResult<DependencyPlan<D::Key, D::Reader>> {
    discover_inner(
        root,
        request,
        &limits,
        resolver,
        first,
        existing_edges,
        find_existing,
    )
    .map_err(|error| error.at_stage(LoadStage::Discover))
}

fn discover_inner<D: DependencyResolver>(
    root: D::Key,
    request: LoadRequest,
    limits: &DependencyLimits,
    resolver: &mut D,
    first: usize,
    existing_edges: usize,
    find_existing: impl Fn(&D::Key) -> Option<usize>,
) -> LoadResult<DependencyPlan<D::Key, D::Reader>> {
    limits.check_image_count(first as u64 + 1)?;
    limits.check_edge_count(existing_edges as u64)?;
    let mut plan = DependencyPlan {
        images: Vec::new(),
        edges: Vec::new(),
    };
    let mut input_bytes = 0;
    plan.images.try_reserve(1).map_err(|_| out_of_memory())?;
    plan.images.push(open_image(
        resolver,
        root,
        request,
        0,
        limits,
        &mut input_bytes,
    )?);

    let provider_request = request.with_purpose(LoadPurpose::SharedObject);
    // The image list doubles as the queue because new providers are appended.
    let mut requester = 0;
    while requester < plan.images.len() {
        let image = &plan.images[requester];
        let names = read_needed(&image.image, existing_edges + plan.edges.len(), limits)?;
        let depth = image.depth;
        plan.edges
            .try_reserve(names.len())
            .map_err(|_| out_of_memory())?;

        for (needed_index, name) in names.into_iter().enumerate() {
            let context = || ErrorContext::Dependency {
                requester: first + requester,
                needed_index,
            };
            let key = resolver
                .resolve(&plan.images[requester].key, &name)
                .map_err(|error| error.with_context(context()))?;
            let provider =
                if let Some(index) = plan.images.iter().position(|image| image.key == key) {
                    if index == 0 {
                        request
                            .profile()
                            .check_root_as_dependency(request.purpose())
                            .map_err(|error| error.with_context(context()))?;
                    }
                    first + index
                } else if let Some(index) = find_existing(&key) {
                    if index == 0 {
                        request
                            .profile()
                            .check_root_as_dependency(LoadPurpose::Executable)
                            .map_err(|error| error.with_context(context()))?;
                    }
                    index
                } else {
                    let index = plan.images.len();
                    let depth = depth + 1;
                    limits.check_image_count(first as u64 + index as u64 + 1)?;
                    limits.check_depth(depth)?;
                    plan.images.try_reserve(1).map_err(|_| out_of_memory())?;
                    let image = open_image(
                        resolver,
                        key,
                        provider_request,
                        depth,
                        limits,
                        &mut input_bytes,
                    )
                    .map_err(|error| error.with_context(context()))?;
                    plan.images.push(image);
                    first + index
                };
            plan.edges.push(DependencyEdge {
                requester: first + requester,
                provider,
                name,
            });
        }
        requester += 1;
    }
    Ok(plan)
}

fn open_image<D: DependencyResolver>(
    resolver: &mut D,
    key: D::Key,
    request: LoadRequest,
    depth: u32,
    limits: &DependencyLimits,
    input_bytes: &mut u64,
) -> LoadResult<DependencyImage<D::Key, D::Reader>> {
    let reader = resolver.open(&key)?;
    *input_bytes = input_bytes
        .checked_add(reader.len()?)
        .ok_or_else(|| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))?;
    limits.check_input_bytes(*input_bytes)?;
    let image = ImageLoader::new(reader, request).prepare_layout()?;
    let soname = if let Some(dynamic) = image.dynamic()
        && let Some(offset) = dynamic.value(DT_SONAME)
    {
        let table = string_table(&image, dynamic)?;
        Some(read_name(
            image.reader(),
            table,
            DT_SONAME,
            offset,
            limits.max_name_len(),
        )?)
    } else {
        None
    };
    Ok(DependencyImage {
        key,
        depth,
        soname,
        image,
    })
}

fn read_needed(
    image: &PlannedImage<impl ElfReader>,
    existing_edges: usize,
    limits: &DependencyLimits,
) -> LoadResult<Vec<Vec<u8>>> {
    let Some(dynamic) = image.dynamic() else {
        return Ok(Vec::new());
    };
    let count = dynamic.needed().count();
    if count == 0 {
        return Ok(Vec::new());
    }
    limits.check_edge_count(existing_edges as u64 + count as u64)?;
    let table = string_table(image, dynamic)?;
    let mut names = Vec::new();
    names
        .try_reserve_exact(count)
        .map_err(|_| out_of_memory())?;
    for offset in dynamic.needed() {
        names.push(read_name(
            image.reader(),
            table,
            DT_NEEDED,
            offset,
            limits.max_name_len(),
        )?);
    }
    Ok(names)
}

fn string_table(
    image: &PlannedImage<impl ElfReader>,
    dynamic: &DynamicInfo,
) -> LoadResult<FileRange> {
    dynamic
        .string_file_range(image.segments())?
        .ok_or_else(|| bad_name(DT_STRTAB, 0))
}

fn read_name(
    reader: &impl ElfReader,
    table: FileRange,
    tag: u64,
    offset: u64,
    max_len: u32,
) -> LoadResult<Vec<u8>> {
    let name = read_string(reader, table, offset, max_len)?;
    if name.is_empty() {
        return Err(bad_name(tag, offset));
    }
    Ok(name)
}

fn bad_name(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag { tag, value },
    )
}

fn out_of_memory() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}
