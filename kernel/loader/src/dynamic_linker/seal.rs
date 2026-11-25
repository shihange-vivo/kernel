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

//! Finalize a relocated graph by validating callbacks and sealing each image.

use alloc::vec::Vec;

use super::{reserve, DependencyEdge, ExportedSymbols, LinkedLifecycle};
use crate::{
    error::LoadStage,
    image::RelocatedImage,
    load::SealedBatch,
    memory::{ImageMapping, TargetAddress},
    CodeCache, LoadResult, LoadedImages, LoadedObject,
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
    pub(super) const fn new(
        key: K,
        soname: Option<Vec<u8>>,
        image: RelocatedImage<A>,
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
    // Index of the first image in this batch within the full group.
    first: usize,
}

impl<K, A: ImageMapping> LinkedImages<K, A> {
    pub(super) const fn new(
        images: Vec<LinkedImage<K, A>>,
        edges: Vec<DependencyEdge>,
        first: usize,
    ) -> Self {
        Self {
            images,
            edges,
            first,
        }
    }

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
        LinkedLifecycle::build(&self.edges, plans, self.first)
    }

    /// Finalize the graph and transfer all mappings into one owning result.
    /// Lifecycle validation covers the whole graph before publishing code or
    /// tightening RELRO. On error every mapping is dropped.
    pub fn seal<C: CodeCache + ?Sized>(self, cache: &mut C) -> LoadResult<LoadedImages<K, A>>
    where
        K: Eq,
    {
        let profile = *self.images[0].image.profile();
        let batch = self.seal_batch(cache)?;
        Ok(LoadedImages::new(batch, profile))
    }

    pub(super) fn seal_batch<C: CodeCache + ?Sized>(
        self,
        cache: &mut C,
    ) -> LoadResult<SealedBatch<K, A>> {
        let (plans, mut init_order) = self.plan_lifecycle()?.into_parts();
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
        for index in &mut init_order {
            *index += self.first;
        }
        Ok(SealedBatch::new(images, self.edges, init_order))
    }
}
