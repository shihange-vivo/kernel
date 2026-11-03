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

//! Prepared kernel publication: all validation/storage precedes ownership transfer.
use super::{
    adapters::{
        flat_memory::{FlatBackingPin, FlatImageMemory},
        system_paths::{SystemLibraryKey, SystemLibraryPaths},
    },
    loader::{loader_error, loader_oom},
    registry::{
        SystemCandidateBacking, SystemDsoLease, SystemDsoRegistry, SystemInitBatch,
        SystemPublication,
    },
    repository::{KernelImagePin, KernelReservation, PinBacking},
};
use alloc::{sync::Arc, vec::Vec};
use blueos_loader::{
    memory::{AllocationLease, ImageMemory},
    ImageHandle, ImagePin, LoadPublisher, LoadResourceParts, LoadResources, LoadResult,
    PublicationManifest,
};
use spin::Mutex;

#[must_use]
struct OwnedResources {
    private: Vec<AllocationLease>,
    failed: Vec<AllocationLease>,
    leases: Vec<SystemDsoLease>,
    pins: Vec<KernelImagePin>,
    imports: Vec<KernelImagePin>,
}
#[must_use = "the backing owns allocations and retained providers"]
pub(crate) struct ReceiptBacking {
    resources: Mutex<OwnedResources>,
    memory: FlatImageMemory,
    // These physical references also cover new Initializing system images. If init fails,
    // a concurrent link's namespace pin still prevents their bytes from being freed.
    _physical: Vec<FlatBackingPin>,
}
impl ReceiptBacking {
    pub(crate) fn retain_failed_system_allocations(&self, allocations: Vec<AllocationLease>) {
        self.resources.lock().failed = allocations;
    }
}
impl Drop for ReceiptBacking {
    fn drop(&mut self) {
        let resources = self.resources.get_mut();
        for allocation in resources
            .private
            .drain(..)
            .chain(resources.failed.drain(..))
        {
            self.memory.release_committed(allocation);
        }
    }
}
#[must_use = "install the receipt or drop it to release its resources"]
pub struct KernelLinkReceipt {
    backing: Arc<ReceiptBacking>,
    pending: Option<SystemInitBatch>,
    images: Vec<ImageHandle>,
}
impl KernelLinkReceipt {
    pub(crate) fn take_pending(&mut self) -> LoadResult<SystemInitBatch> {
        self.pending.take().ok_or_else(loader_error)
    }
    pub(crate) fn backing(&self) -> Arc<ReceiptBacking> {
        self.backing.clone()
    }
    pub(crate) fn pin(&self, image: &ImageHandle) -> LoadResult<KernelImagePin> {
        if !self
            .images
            .iter()
            .any(|i| i.instance_id() == image.instance_id())
        {
            return Err(loader_error());
        }
        Ok(KernelImagePin {
            image: image.clone(),
            backing: PinBacking::Namespace(self.backing.clone()),
        })
    }
    pub fn retain_failed_system_allocations(&mut self, allocations: Vec<AllocationLease>) {
        self.backing.retain_failed_system_allocations(allocations);
    }
    pub fn attach_system_leases(&mut self, leases: Vec<SystemDsoLease>) {
        // Initialization completes once. Moving the preallocated result also avoids a new
        // allocation after registry Ready publication, even while namespace pins exist.
        self.backing.resources.lock().leases = leases;
    }
    pub(crate) fn counts(&self) -> (usize, usize) {
        let resources = self.backing.resources.lock();
        (
            resources.private.len(),
            resources.leases.len()
                + resources
                    .imports
                    .iter()
                    .chain(&resources.pins)
                    .filter(|p| p.image().is_shared())
                    .count(),
        )
    }
}
#[must_use]
struct CandidateMetadata {
    descriptor: ImageHandle,
    fini_plan: Vec<usize>,
    dependency_keys: Vec<SystemLibraryKey>,
    dependencies: Vec<SystemDsoLease>,
    scc_members: Vec<SystemLibraryKey>,
    keep_cached: bool,
}
#[must_use = "commit the prepared publication or drop its reserved metadata"]
pub(crate) struct KernelLinkPreparedBatch {
    receipt: KernelLinkReceipt,
    system: SystemPublication,
    metadata: Vec<(usize, CandidateMetadata)>,
    backings: Vec<SystemCandidateBacking>,
}
pub(crate) struct KernelLinkPublisher {
    memory: FlatImageMemory,
    registry: SystemDsoRegistry,
    catalog: &'static SystemLibraryPaths,
}
impl KernelLinkPublisher {
    pub(crate) fn new(
        memory: FlatImageMemory,
        registry: SystemDsoRegistry,
        catalog: &'static SystemLibraryPaths,
    ) -> Self {
        Self {
            memory,
            registry,
            catalog,
        }
    }
}
impl LoadPublisher<FlatImageMemory, KernelImagePin, KernelReservation> for KernelLinkPublisher {
    type Prepared = KernelLinkPreparedBatch;
    type Owner = KernelLinkReceipt;
    fn prepare(
        &mut self,
        manifest: &PublicationManifest,
        reservation: &KernelReservation,
    ) -> LoadResult<Self::Prepared> {
        let mut private = Vec::new();
        private
            .try_reserve_exact(manifest.private_images())
            .map_err(|_| loader_oom())?;
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(manifest.allocations().len())
            .map_err(|_| loader_oom())?;
        for (_, allocation) in manifest.allocations() {
            physical.push(self.memory.pin(allocation)?);
        }
        let mut images = Vec::new();
        images
            .try_reserve_exact(manifest.images().count() + manifest.retained_images().len())
            .map_err(|_| loader_oom())?;
        images.extend(manifest.images().cloned());
        for image in manifest.retained_images() {
            if !images
                .iter()
                .any(|i| i.instance_id() == image.instance_id())
            {
                images.push(image.clone());
            }
        }
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(reservation.permits.len())
            .map_err(|_| loader_oom())?;
        let mut backings = Vec::new();
        backings
            .try_reserve_exact(reservation.permits.len())
            .map_err(|_| loader_oom())?;
        if reservation.permits.len() != manifest.shared_images() {
            return Err(loader_error());
        }
        // Simulate commit's swap-removals now, while every failure still rolls
        // back. The resulting indices remain valid for the unchanged resource
        // order, so commit never searches for or validates an allocation.
        let mut remaining = Vec::new();
        remaining
            .try_reserve_exact(manifest.allocations().len())
            .map_err(|_| loader_oom())?;
        remaining.extend(
            manifest
                .allocations()
                .iter()
                .map(|(image, _)| image.instance_id()),
        );
        for (key, _) in &reservation.permits {
            let image = manifest
                .allocations()
                .iter()
                .find(|(i, _)| i.is_shared() && i.identity() == key.as_bytes())
                .map(|(i, _)| i)
                .ok_or_else(loader_error)?;
            let keep_cached = self
                .catalog
                .resolve_key(key)
                .ok_or_else(loader_error)?
                .keep_cached;
            let scc_members = image_keys(manifest.shared_component(image))?;
            if scc_members.is_empty() {
                return Err(loader_error());
            }
            let mut dependency_keys = image_keys(manifest.shared_dependencies(image))?;
            dependency_keys.sort();
            dependency_keys.dedup();
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(dependency_keys.len())
                .map_err(|_| loader_oom())?;
            let fini_plan = super::start_storage::build_plan_targets(manifest.image_fini(image))
                .map_err(|_| loader_error())?
                .into_vec();
            let index = remaining
                .iter()
                .position(|id| *id == image.instance_id())
                .ok_or_else(loader_error)?;
            remaining.swap_remove(index);
            metadata.push((
                index,
                CandidateMetadata {
                    descriptor: image.clone(),
                    fini_plan,
                    dependency_keys,
                    dependencies,
                    scc_members,
                    keep_cached,
                },
            ));
        }
        let system = self.registry.prepare_publication(&reservation.permits)?;
        let backing = Arc::new(ReceiptBacking {
            resources: Mutex::new(OwnedResources {
                private,
                failed: Vec::new(),
                leases: Vec::new(),
                pins: Vec::new(),
                imports: Vec::new(),
            }),
            memory: self.memory.clone(),
            _physical: physical,
        });
        Ok(KernelLinkPreparedBatch {
            receipt: KernelLinkReceipt {
                backing,
                pending: None,
                images,
            },
            system,
            metadata,
            backings,
        })
    }
    // SAFETY: the caller supplies this prepare's unchanged resource order.
    // Every removal index and destination capacity was checked in prepare;
    // commit only moves each lease into its preallocated owner.
    unsafe fn commit(
        &mut self,
        mut prepared: Self::Prepared,
        resources: LoadResources<FlatImageMemory, KernelImagePin, KernelReservation>,
    ) -> KernelLinkReceipt {
        // SAFETY: the prepared owner has a sink for every allocation and retains all providers.
        let LoadResourceParts {
            memory: _,
            mut allocations,
            pins,
            reservation,
        } = unsafe { resources.into_parts() };
        for (index, metadata) in prepared.metadata {
            // prepare simulated these exact removals from this resource order.
            let (_, allocation) = allocations.swap_remove(index);
            prepared.backings.push(SystemCandidateBacking {
                descriptor: metadata.descriptor,
                allocation,
                fini_plan: metadata.fini_plan,
                dependency_keys: metadata.dependency_keys,
                dependencies: metadata.dependencies,
                scc_members: metadata.scc_members,
                keep_cached: metadata.keep_cached,
            });
        }
        {
            let mut owned = prepared.receipt.backing.resources.lock();
            for (_, allocation) in allocations {
                owned.private.push(allocation);
            }
            owned.pins = pins;
            owned.imports = reservation.imported;
        }
        prepared.receipt.pending = Some(self.registry.commit_publication(
            prepared.system,
            reservation.permits,
            prepared.backings,
        ));
        prepared.receipt
    }
}
fn image_keys(images: &[ImageHandle]) -> LoadResult<Vec<SystemLibraryKey>> {
    let mut keys = Vec::new();
    keys.try_reserve_exact(images.len())
        .map_err(|_| loader_oom())?;
    for image in images {
        keys.push(SystemLibraryKey::from_bytes(image.identity())?);
    }
    Ok(keys)
}
