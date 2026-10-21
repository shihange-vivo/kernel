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

//! Exact instance pins and RAII closure reservations over the system registry.
use super::{
    adapters::{flat_memory::FlatImageMemory, system_paths::SystemLibraryKey},
    publication::ReceiptBacking,
    registry::{
        AcquireBatchOutcome, LoadPermit, SystemDsoLease, SystemDsoRegistry, SystemSnapshotOutcome,
    },
};
use alloc::{sync::Arc, vec::Vec};
use blueos_loader::{
    ImageCandidate, ImageHandle, ImageInstanceId, ImageKey, ImagePin, ImageRepository,
    LoadReservation, LoadResult, ReservedImage,
};

#[must_use = "pins keep mapped code and its providers alive"]
#[derive(Clone)]
pub(crate) struct KernelImagePin {
    pub(crate) image: ImageHandle,
    pub(crate) backing: PinBacking,
}
#[must_use]
#[derive(Clone)]
pub(crate) enum PinBacking {
    System(Arc<SystemDsoLease>, FlatImageMemory),
    Namespace(Arc<ReceiptBacking>),
}
// SAFETY: registry leases retain the full system provider graph; receipt backings retain
// private allocations, physical system backing pins, and all imported provider pins.
unsafe impl ImagePin for KernelImagePin {
    fn image(&self) -> &ImageHandle {
        &self.image
    }
}
impl KernelImagePin {
    fn system(image: ImageHandle, lease: SystemDsoLease, memory: &FlatImageMemory) -> Self {
        Self {
            image,
            backing: PinBacking::System(Arc::new(lease), memory.clone()),
        }
    }
}
#[must_use = "dropping an unpublished reservation cancels every load permit"]
pub(crate) struct KernelReservation {
    pub(crate) permits: Vec<(SystemLibraryKey, LoadPermit)>,
    reserved: Vec<ReservedImage>,
    pub(crate) imported: Vec<KernelImagePin>,
}
impl LoadReservation for KernelReservation {
    type Pin = KernelImagePin;
    fn reserved(&self) -> &[ReservedImage] {
        &self.reserved
    }
    fn imported(&self) -> &[KernelImagePin] {
        &self.imported
    }
}
#[must_use = "repository snapshots retain live image pins"]
pub(crate) struct KernelImageRepository {
    registry: SystemDsoRegistry,
    known: Vec<KernelImagePin>,
    memory: FlatImageMemory,
}
impl KernelImageRepository {
    pub(crate) fn new(
        registry: SystemDsoRegistry,
        known: Vec<KernelImagePin>,
        memory: FlatImageMemory,
    ) -> Self {
        Self {
            registry,
            known,
            memory,
        }
    }
}
impl ImageRepository for KernelImageRepository {
    type Pin = KernelImagePin;
    type Reservation = KernelReservation;
    fn snapshot(&mut self, key: &ImageKey) -> LoadResult<Option<KernelImagePin>> {
        if let Some(pin) = self.known.iter().find(|p| p.image.key() == key) {
            return Ok(Some(pin.clone()));
        }
        if key.scope() != 0 {
            return Ok(None);
        }
        loop {
            match self
                .registry
                .snapshot(SystemLibraryKey::from_bytes(key.identity())?)?
            {
                SystemSnapshotOutcome::Vacant => return Ok(None),
                SystemSnapshotOutcome::Pending(wait) => wait.wait(),
                SystemSnapshotOutcome::Ready(lease, image) => {
                    return Ok(Some(KernelImagePin::system(image, lease, &self.memory)))
                }
            }
        }
    }
    fn pin_exact(&mut self, id: &ImageInstanceId) -> LoadResult<KernelImagePin> {
        if let Some(pin) = self.known.iter().find(|p| p.image.instance_id() == *id) {
            return Ok(pin.clone());
        }
        self.registry
            .pin_exact(*id)
            .map(|(lease, image)| KernelImagePin::system(image, lease, &self.memory))
    }
    fn acquire(&mut self, candidates: &[ImageCandidate]) -> LoadResult<KernelReservation> {
        let mut keys = Vec::new();
        let mut reserved = Vec::new();
        let mut imported = Vec::new();
        keys.try_reserve_exact(candidates.len())
            .map_err(|_| super::loader::loader_oom())?;
        reserved
            .try_reserve_exact(candidates.len())
            .map_err(|_| super::loader::loader_oom())?;
        imported
            .try_reserve_exact(candidates.len())
            .map_err(|_| super::loader::loader_oom())?;
        for c in candidates {
            if c.managed {
                keys.push(SystemLibraryKey::from_bytes(c.key.identity())?);
            }
        }
        let batch = loop {
            match self.registry.acquire_batch(&keys)? {
                AcquireBatchOutcome::Acquired(b) => break b,
                AcquireBatchOutcome::Pending(w) => w.wait(),
            }
        };
        for (_, lease, image) in batch.imports {
            imported.push(KernelImagePin::system(image, lease, &self.memory));
        }
        for c in candidates {
            if !imported.iter().any(|p| p.image.key() == &c.key) {
                reserved.push(ReservedImage {
                    key: c.key.clone(),
                    instance: ImageInstanceId::fresh()?,
                });
            }
        }
        Ok(KernelReservation {
            permits: batch.loads,
            reserved,
            imported,
        })
    }
}
