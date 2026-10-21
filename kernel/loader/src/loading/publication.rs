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

//! Prepared publication, guarding resource handoff, and host ownership.
use super::{
    loaded::{build_facts, handle, LoadFacts},
    planning::LoadPlan,
};
use crate::{
    dynamic_linker::{
        CommittingLinkProduct, ImageOwnership, LifecyclePlans, LinkContext, LinkPublisher,
        PreparedLinkManifest, RelocationBinding,
    },
    error::{oom, overflow},
    memory::{
        AllocationLease, ImageAllocation, ImageMemory, ImageProtectionMemory, MutationProgress,
    },
    ImageHandle, ImagePin, LoadReservation, LoadResult, LoadedImage,
};
use alloc::vec::Vec;
use core::ops::Deref;

/// Complete immutable facts available before the host adopts allocations.
pub struct PublicationManifest {
    pub(crate) image: LoadedImage<()>,
    pub(crate) allocations: Vec<(ImageHandle, ImageAllocation)>,
}
impl Deref for PublicationManifest {
    type Target = LoadedImage<()>;
    fn deref(&self) -> &Self::Target {
        &self.image
    }
}
impl PublicationManifest {
    pub fn profile(&self) -> crate::profile::LoadProfile {
        self.images().next().expect("root image").profile()
    }
    pub fn allocations(&self) -> &[(ImageHandle, ImageAllocation)] {
        &self.allocations
    }
    pub fn execution_domain(&self) -> crate::ExecutionDomainId {
        self.images().next().expect("root image").execution_domain()
    }
    pub fn private_images(&self) -> usize {
        self.allocations
            .iter()
            .filter(|(i, _)| !i.is_shared())
            .count()
    }
    pub fn shared_images(&self) -> usize {
        self.allocations.len() - self.private_images()
    }
}

pub trait LoadPublisher<M: ImageProtectionMemory, P: ImagePin, B: LoadReservation<Pin = P>> {
    type Prepared;
    type Owner;
    fn prepare(
        &mut self,
        manifest: &PublicationManifest,
        reservation: &B,
    ) -> LoadResult<Self::Prepared>;
    /// # Safety
    /// The token and resources must belong to this prepare. Adopt every allocation and retained pin,
    /// without allocation, failure, application callbacks or panic.
    unsafe fn commit(
        &mut self,
        prepared: Self::Prepared,
        resources: LoadResources<M, P, B>,
    ) -> Self::Owner;
}

#[must_use = "the publisher must adopt every allocation and retained provider"]
pub struct LoadResources<M: ImageMemory, P: ImagePin, B: LoadReservation<Pin = P>> {
    memory: Option<M>,
    allocations: Vec<(ImageHandle, AllocationLease)>,
    pins: Vec<P>,
    reservation: Option<B>,
}
impl<M: ImageMemory, P: ImagePin, B: LoadReservation<Pin = P>> LoadResources<M, P, B> {
    /// # Safety
    /// The caller assumes all release authority, including the memory backing and provider pins.
    pub unsafe fn into_parts(mut self) -> (M, Vec<(ImageHandle, AllocationLease)>, Vec<P>, B) {
        (
            self.memory.take().expect("resource memory"),
            core::mem::take(&mut self.allocations),
            core::mem::take(&mut self.pins),
            self.reservation.take().expect("resource reservation"),
        )
    }
}
impl<M: ImageMemory, P: ImagePin, B: LoadReservation<Pin = P>> Drop for LoadResources<M, P, B> {
    fn drop(&mut self) {
        if let Some(memory) = &mut self.memory {
            while let Some((_, lease)) = self.allocations.pop() {
                memory.release_committed(lease);
            }
        }
    }
}

#[must_use = "publish the prepared load or drop it to roll back"]
pub struct PreparedLoad<M: ImageProtectionMemory, P: ImagePin, B: LoadReservation<Pin = P>> {
    pub(crate) memory: Option<M>,
    pub(crate) allocations: Vec<(ImageHandle, AllocationLease)>,
    pub(crate) pins: Vec<P>,
    pub(crate) reservation: Option<B>,
    pub(crate) manifest: Option<PublicationManifest>,
}
impl<M: ImageProtectionMemory, P: ImagePin, B: LoadReservation<Pin = P>> PreparedLoad<M, P, B> {
    pub fn manifest(&self) -> &PublicationManifest {
        self.manifest.as_ref().expect("prepared manifest")
    }
    pub fn publish<U: LoadPublisher<M, P, B>>(
        mut self,
        publisher: &mut U,
    ) -> LoadResult<LoadedImage<U::Owner>> {
        let token = publisher.prepare(
            self.manifest(),
            self.reservation.as_ref().expect("reservation"),
        )?;
        let manifest = self.manifest.take().expect("manifest");
        let resources = LoadResources {
            memory: self.memory.take(),
            allocations: core::mem::take(&mut self.allocations),
            pins: core::mem::take(&mut self.pins),
            reservation: self.reservation.take(),
        };
        // SAFETY: the token and guarded resources were produced for the same complete manifest.
        let owner = unsafe { publisher.commit(token, resources) };
        Ok(LoadedImage::new(owner, manifest.image.facts))
    }
}
impl<M: ImageProtectionMemory, P: ImagePin, B: LoadReservation<Pin = P>> Drop
    for PreparedLoad<M, P, B>
{
    fn drop(&mut self) {
        if let Some(memory) = &mut self.memory {
            while let Some((_, lease)) = self.allocations.pop() {
                memory.abort_image(lease, MutationProgress::ProtectionModified);
            }
        }
    }
}

/// Private-only host publisher retaining resources until the returned owner is dropped.
pub struct RetainResources;
impl<M: ImageProtectionMemory, P: ImagePin, B: LoadReservation<Pin = P>> LoadPublisher<M, P, B>
    for RetainResources
{
    type Prepared = ();
    type Owner = LoadResources<M, P, B>;
    fn prepare(&mut self, m: &PublicationManifest, _: &B) -> LoadResult<()> {
        if m.shared_images() != 0 {
            return Err(crate::error::invalid());
        }
        Ok(())
    }
    unsafe fn commit(&mut self, _: (), resources: Self::Owner) -> Self::Owner {
        resources
    }
}

/// Internal adapter finishing the ELF transaction while the outer prepared guard remains armed.
pub(crate) struct CapturePublisher<'a, S, R> {
    pub(crate) plan: &'a LoadPlan<S, R>,
    pub(crate) facts: Option<LoadFacts>,
    handles: Vec<ImageHandle>,
    allocations: Vec<(ImageHandle, AllocationLease)>,
}
impl<'a, S, R> CapturePublisher<'a, S, R> {
    pub(crate) fn new(plan: &'a LoadPlan<S, R>) -> Self {
        Self {
            plan,
            facts: None,
            handles: Vec::new(),
            allocations: Vec::new(),
        }
    }
}
impl<S, R> LinkPublisher for CapturePublisher<'_, S, R> {
    type PreparedBatch = ();
    type Receipt = Vec<(ImageHandle, AllocationLease)>;
    fn prepare_metadata(
        &mut self,
        context: &LinkContext,
        plans: &LifecyclePlans,
        bindings: &[RelocationBinding],
    ) -> LoadResult<u64> {
        self.facts = Some(build_facts(self.plan, context, plans, bindings)?);
        self.handles
            .try_reserve_exact(context.images().len())
            .map_err(|_| oom())?;
        self.allocations
            .try_reserve_exact(context.images().len())
            .map_err(|_| oom())?;
        for image in context.images() {
            if matches!(
                image.ownership(),
                ImageOwnership::SessionPrivate | ImageOwnership::SystemCandidate
            ) {
                self.handles.push(handle(image));
            }
        }
        self.facts
            .as_ref()
            .expect("facts")
            .metadata_bytes()
            .checked_add(self.plan.metadata_bytes()?)
            .and_then(|b| {
                b.checked_add(
                    (self.handles.capacity() * core::mem::size_of::<ImageHandle>()
                        + self.allocations.capacity()
                            * (core::mem::size_of::<(ImageHandle, AllocationLease)>()
                                + core::mem::size_of::<(ImageHandle, ImageAllocation)>()))
                        as u64,
                )
            })
            .ok_or_else(overflow)
    }
    fn prepare_batch(&mut self, _: &PreparedLinkManifest) -> LoadResult<()> {
        Ok(())
    }
    unsafe fn commit_batch(&mut self, _: (), product: CommittingLinkProduct) -> Self::Receipt {
        for pair in self.handles.drain(..).zip(product.into_leases()) {
            self.allocations.push(pair);
        }
        core::mem::take(&mut self.allocations)
    }
}
