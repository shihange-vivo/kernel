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

//! Publication preparation and allocation handoff to the host backend.

use alloc::vec::Vec;

use crate::{
    dynamic_linker::{
        CommittingLinkProduct, ImageOwnership, LifecyclePlans, LinkContext, LinkPublisher,
        PreparedLinkManifest, RelocationBinding,
    },
    error::{oom, overflow},
    loaded::{build_facts, handle, LoadFacts},
    memory::AllocationLease,
    planning::LoadPlan,
    ImageHandle, LoadResult, LoaderBackend,
};

/// Allocation counts needed by a backend to reserve its ownership sinks.
pub struct Publication {
    private: usize,
    shared: usize,
    imported: usize,
}

impl Publication {
    pub const fn private_images(&self) -> usize {
        self.private
    }
    pub const fn shared_images(&self) -> usize {
        self.shared
    }
    pub const fn imported_shared_images(&self) -> usize {
        self.imported
    }
}

/// Unique allocation authorities, paired with opaque image handles.
pub struct CommittedAllocations {
    images: Vec<ImageHandle>,
    leases: Vec<AllocationLease>,
}

impl CommittedAllocations {
    pub fn into_images(self) -> impl Iterator<Item = (ImageHandle, AllocationLease)> {
        self.images.into_iter().zip(self.leases)
    }
}

pub(crate) struct BackendPublisher<'a, B: LoaderBackend> {
    pub(crate) backend: &'a mut B,
    plan: &'a LoadPlan<B::Source, B::Reader>,
    pub(crate) facts: Option<LoadFacts>,
    allocations: Vec<ImageHandle>,
}

impl<'a, B: LoaderBackend> BackendPublisher<'a, B> {
    pub(crate) fn new(backend: &'a mut B, plan: &'a LoadPlan<B::Source, B::Reader>) -> Self {
        Self {
            backend,
            plan,
            facts: None,
            allocations: Vec::new(),
        }
    }
}

impl<B: LoaderBackend> LinkPublisher for BackendPublisher<'_, B> {
    type PreparedBatch = B::PreparedPublication;
    type Receipt = B::Receipt;

    fn prepare_metadata(
        &mut self,
        context: &LinkContext,
        plans: &LifecyclePlans,
        bindings: &[RelocationBinding],
    ) -> LoadResult<u64> {
        self.facts = Some(build_facts(self.plan, context, plans, bindings)?);
        self.allocations
            .try_reserve_exact(context.images().len())
            .map_err(|_| oom())?;
        for image in context.images() {
            if matches!(
                image.ownership(),
                ImageOwnership::SessionPrivate | ImageOwnership::SystemCandidate
            ) {
                self.allocations.push(handle(image));
            }
        }
        let facts = self.facts.as_ref().expect("facts prepared above");
        let bytes = facts
            .metadata_bytes()
            .checked_add(self.plan.metadata_bytes()?)
            .and_then(|bytes| {
                bytes.checked_add(
                    (self.allocations.capacity() * core::mem::size_of::<ImageHandle>()) as u64,
                )
            })
            .ok_or_else(overflow)?;
        Ok(bytes)
    }
    fn prepare_batch(
        &mut self,
        manifest: &PreparedLinkManifest,
    ) -> LoadResult<Self::PreparedBatch> {
        let mut publication = Publication {
            private: 0,
            shared: 0,
            imported: 0,
        };
        for image in manifest.link_map() {
            match image.ownership() {
                ImageOwnership::SessionPrivate => publication.private += 1,
                ImageOwnership::SystemCandidate => publication.shared += 1,
                ImageOwnership::ExternalReady => publication.imported += 1,
                ImageOwnership::NamespaceReady => {}
            }
        }
        self.backend.prepare_publication(&publication)
    }
    unsafe fn commit_batch(
        &mut self,
        prepared: Self::PreparedBatch,
        product: CommittingLinkProduct,
    ) -> Self::Receipt {
        let allocations = CommittedAllocations {
            images: core::mem::take(&mut self.allocations),
            leases: product.into_leases(),
        };
        // SAFETY: the internal publisher prepared these inputs for this backend.
        unsafe { self.backend.commit_publication(prepared, allocations) }
    }
}
