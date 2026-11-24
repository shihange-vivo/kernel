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

//! Load and finalize a whole ELF dependency graph.

use alloc::vec::Vec;

use super::{LoadAndLinkRequest, LoadedImage};
use crate::{
    dynamic_linker::{discover, link, DependencyEdge, DependencyResolver, ExportedSymbols},
    memory::{ImageMapping, TargetAddress},
    CodeCache, ImageAllocator, LoadResult,
};

/// A finalized ELF in a loaded dependency graph.
#[must_use = "retain the loaded graph while its images are in use"]
pub struct LoadedObject<K, A: ImageMapping> {
    key: K,
    soname: Option<Vec<u8>>,
    image: LoadedImage<A>,
    exports: Option<ExportedSymbols>,
}

impl<K, A: ImageMapping> LoadedObject<K, A> {
    pub(crate) fn new(
        key: K,
        soname: Option<Vec<u8>>,
        image: LoadedImage<A>,
        exports: Option<ExportedSymbols>,
    ) -> Self {
        Self {
            key,
            soname,
            image,
            exports,
        }
    }

    pub const fn key(&self) -> &K {
        &self.key
    }

    pub fn soname(&self) -> Option<&[u8]> {
        self.soname.as_deref()
    }

    /// The finalized image. Its symbols can refer to other images in the graph.
    pub const fn image(&self) -> &LoadedImage<A> {
        &self.image
    }

    /// Export index captured when the request set an export budget.
    pub fn exports(&self) -> Option<&ExportedSymbols> {
        self.exports.as_ref()
    }
}

/// Owns every mapping in a finalized dependency graph. The host runs the
/// callbacks and entry, and keeps this owner alive until the last use of the
/// graph's code or data. Dropping the owner releases the mappings.
#[must_use = "retain the loaded images for as long as any of their code or data is in use"]
pub struct LoadedImages<K, A: ImageMapping> {
    images: Vec<LoadedObject<K, A>>,
    edges: Vec<DependencyEdge>,
    init_order: Vec<usize>,
}

impl<K, A: ImageMapping> LoadedImages<K, A> {
    pub(crate) fn new(
        images: Vec<LoadedObject<K, A>>,
        edges: Vec<DependencyEdge>,
        init_order: Vec<usize>,
    ) -> Self {
        Self {
            images,
            edges,
            init_order,
        }
    }

    /// The root image with its runtime entry and program header table.
    pub fn root(&self) -> &LoadedImage<A> {
        self.images[0].image()
    }

    /// The root and its dependencies in breadth-first discovery order.
    pub fn images(&self) -> &[LoadedObject<K, A>] {
        &self.images
    }

    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }

    /// The root's preinitializers, for execution before any image initialization.
    pub fn preinit(&self) -> &[TargetAddress] {
        self.root().lifecycle().preinit()
    }

    /// Constructors in dependency order, with cycle members in discovery order.
    pub fn init(&self) -> impl Iterator<Item = TargetAddress> + '_ {
        self.init_order
            .iter()
            .flat_map(|&index| self.images[index].image.lifecycle().init().iter().copied())
    }

    /// Destructors in reverse image order, preserving each image's fini order.
    pub fn fini(&self) -> impl Iterator<Item = TargetAddress> + '_ {
        self.init_order
            .iter()
            .rev()
            .flat_map(|&index| self.images[index].image.lifecycle().fini().iter().copied())
    }
}

/// Discover, eagerly relocate and finalize the root and its dependencies.
/// The resolver opens the root by key and selects dependencies in the
/// requester's context. The allocator provides a single target address space,
/// and the cache backend publishes code for the host's execution contexts.
/// The result contains the ordered callbacks for the host to invoke.
pub fn load_and_link<D, M, C>(
    root: D::Key,
    request: LoadAndLinkRequest,
    resolver: &mut D,
    allocator: M,
    cache: &mut C,
) -> LoadResult<LoadedImages<D::Key, M::Allocation>>
where
    D: DependencyResolver,
    M: ImageAllocator,
    C: CodeCache + ?Sized,
{
    discover(
        root,
        request.load_request,
        request.dependency_limits,
        resolver,
    )
    .and_then(|plan| link(plan, request.link_limits, allocator))
    .and_then(|linked| linked.seal(cache))
}
