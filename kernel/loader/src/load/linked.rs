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

use alloc::{collections::TryReserveError, vec::Vec};

use super::{LoadAndLinkRequest, LoadedImage};
use crate::{
    dynamic_linker::{
        discover, link, lookup_symbol, prepare_plugin, DependencyEdge, DependencyResolver,
        ExportedSymbols,
    },
    error::{ErrorContext, ExistingImageReason, LoadErrorKind, LoadStage},
    memory::{ImageMapping, TargetAddress},
    profile::LoadProfile,
    CodeCache, ImageAllocator, LoadError, LoadResult,
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
    pub(crate) const fn new(
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
    pub const fn exports(&self) -> Option<&ExportedSymbols> {
        self.exports.as_ref()
    }
}

/// The finalized images and metadata from one startup or plugin load.
#[must_use = "retain the sealed batch to keep its mappings alive"]
pub(crate) struct SealedBatch<K, A: ImageMapping> {
    images: Vec<LoadedObject<K, A>>,
    edges: Vec<DependencyEdge>,
    /// Image indexes in initialization order, relative to the full group.
    init_order: Vec<usize>,
}

impl<K, A: ImageMapping> SealedBatch<K, A> {
    pub(crate) const fn new(
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
}

/// Whether a plugin was already present or needs its constructors run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginLoad {
    Existing(usize),
    Pending,
}

/// Owns the finalized dependency graph and any plugin awaiting publication.
/// The host runs the callbacks and entry, and keeps this owner alive until
/// the last use of the graph's code or data. Dropping it releases all mappings.
#[must_use = "retain the loaded images for as long as any of their code or data is in use"]
pub struct LoadedImages<K, A: ImageMapping> {
    images: Vec<LoadedObject<K, A>>,
    edges: Vec<DependencyEdge>,
    init_order: Vec<usize>,
    startup_count: usize,
    profile: LoadProfile,
    pending: Option<SealedBatch<K, A>>,
}

impl<K: Eq, A: ImageMapping> LoadedImages<K, A> {
    pub(crate) fn new(batch: SealedBatch<K, A>, profile: LoadProfile) -> Self {
        Self {
            startup_count: batch.images.len(),
            images: batch.images,
            edges: batch.edges,
            init_order: batch.init_order,
            profile,
            pending: None,
        }
    }

    /// The root image with its runtime entry and program header table.
    pub fn root(&self) -> &LoadedImage<A> {
        self.images[0].image()
    }

    /// The startup graph, followed by published plugin images.
    /// Indexes remain stable throughout the group's lifetime.
    pub fn images(&self) -> &[LoadedObject<K, A>] {
        &self.images
    }

    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }

    /// Find an export starting at an image index in this group, then visit its
    /// `DT_NEEDED` dependencies in breadth-first order. Each visited image must
    /// have retained its export index. The returned address is valid while the
    /// group is alive. The host controls which image indexes are available to
    /// callers and when their code or data may be used.
    pub fn lookup_symbol(&self, image: usize, name: &[u8]) -> LoadResult<Option<TargetAddress>> {
        lookup_symbol(self, image, name)
    }

    pub(crate) const fn startup_count(&self) -> usize {
        self.startup_count
    }

    /// Image indexes in callback order. A plugin load appends its new indexes.
    pub fn init_order(&self) -> &[usize] {
        &self.init_order
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

    pub(crate) fn find(&self, key: &K) -> Option<usize> {
        self.images.iter().position(|image| image.key() == key)
    }

    /// Append a plugin before startup, then run the complete callback plan at
    /// startup. The allocator must serve the group's target address space.
    /// Use `begin_plugin_load` when extending a running group.
    pub fn load_plugin<D, M, C>(
        &mut self,
        key: K,
        request: LoadAndLinkRequest,
        resolver: &mut D,
        allocator: M,
        cache: &mut C,
    ) -> LoadResult<usize>
    where
        D: DependencyResolver<Key = K>,
        M: ImageAllocator<Allocation = A>,
        C: CodeCache + ?Sized,
    {
        match self.begin_plugin_load(key, request, resolver, allocator, cache)? {
            PluginLoad::Existing(index) => Ok(index),
            PluginLoad::Pending => Ok(self.finish_plugin_load().expect("plugin was just prepared")),
        }
    }

    /// Prepare a plugin while holding its new mappings outside the visible graph.
    /// The startup graph precedes the plugin and its dependencies for symbol
    /// lookup. Enable export indexing when loading potential providers.
    ///
    /// The allocator must serve the group's target address space. A running
    /// group must finish its previous constructors first. The host serializes
    /// operations and reports completion after running `pending_plugin_init`.
    /// A pending batch remains owned by the group until completion or discard.
    pub fn begin_plugin_load<D, M, C>(
        &mut self,
        key: K,
        request: LoadAndLinkRequest,
        resolver: &mut D,
        allocator: M,
        cache: &mut C,
    ) -> LoadResult<PluginLoad>
    where
        D: DependencyResolver<Key = K>,
        M: ImageAllocator<Allocation = A>,
        C: CodeCache + ?Sized,
    {
        if let Some(index) = self
            .check_plugin(&key, request.profile())
            .map_err(|error| error.at_stage(LoadStage::Discover))?
        {
            return Ok(PluginLoad::Existing(index));
        }
        let plugin = prepare_plugin(self, key, request, resolver, allocator, cache)?;
        self.reserve_batch(&plugin).map_err(|_| {
            LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::Seal)
        })?;
        self.pending = Some(plugin);
        Ok(PluginLoad::Pending)
    }

    /// Constructors for the pending batch, in dependency order. `Some` with
    /// an empty iterator still means a batch is pending.
    pub fn pending_plugin_init(&self) -> Option<impl Iterator<Item = TargetAddress> + '_> {
        let first = self.images.len();
        self.pending.as_ref().map(|batch| {
            batch.init_order.iter().flat_map(move |&index| {
                batch.images[index - first]
                    .image
                    .lifecycle()
                    .init()
                    .iter()
                    .copied()
            })
        })
    }

    /// Publish the pending batch after successful initialization. Returns the
    /// plugin's stable image index. All required capacity was reserved in begin.
    pub fn finish_plugin_load(&mut self) -> Option<usize> {
        let mut batch = self.pending.take()?;
        let index = self.images.len();
        self.images.append(&mut batch.images);
        self.edges.append(&mut batch.edges);
        self.init_order.append(&mut batch.init_order);
        Some(index)
    }

    /// Release the pending mappings. The host must ensure their callbacks,
    /// code and data can no longer be used before discarding the batch.
    pub fn cancel_plugin_load(&mut self) {
        drop(self.pending.take());
    }

    fn check_plugin(&self, key: &K, profile: &LoadProfile) -> LoadResult<Option<usize>> {
        if self.pending.is_some() {
            return Err(LoadError::new(
                LoadErrorKind::PluginLoadPending,
                ErrorContext::None,
            ));
        }
        if profile != &self.profile {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            ));
        }
        let index = self.find(key);
        if let Some(index @ 0) = index {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ExistingImage {
                    index,
                    base: self.root().allocation().base(),
                    reason: ExistingImageReason::RootAsPlugin,
                },
            ));
        }
        Ok(index)
    }

    fn reserve_batch(&mut self, batch: &SealedBatch<K, A>) -> Result<(), TryReserveError> {
        self.images.try_reserve(batch.images.len())?;
        self.edges.try_reserve(batch.edges.len())?;
        self.init_order.try_reserve(batch.init_order.len())?;
        Ok(())
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
    let (load_request, dependency_limits, link_limits) = request.into_parts();
    discover(root, load_request, dependency_limits, resolver)
        .and_then(|plan| link(plan, link_limits, allocator))
        .and_then(|linked| linked.seal(cache))
}
