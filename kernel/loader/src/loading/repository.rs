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

//! Existing-instance pins and atomic reservation of a complete load closure.
use crate::{
    error::{invalid, oom},
    ArtifactId, ImageHandle, ImageInstanceId, ImageKey, LoadResult,
};
use alloc::vec::Vec;

/// A host-owned reference to one exact mapped instance.
///
/// # Safety
/// Implementors keep this descriptor's backing and retained providers alive until drop.
/// Dropping the pin must not execute application code.
pub unsafe trait ImagePin {
    fn image(&self) -> &ImageHandle;
}

#[must_use = "keep namespace providers pinned until publication"]
pub struct NamespaceSnapshot<P: ImagePin> {
    pub(crate) pins: Vec<P>,
    pub(crate) global: Vec<ImageInstanceId>,
}
impl<P: ImagePin> NamespaceSnapshot<P> {
    pub fn new(pins: Vec<P>, global: Vec<ImageInstanceId>) -> LoadResult<Self> {
        for (i, pin) in pins.iter().enumerate() {
            if pin.image().profile() != pins[0].image().profile() {
                return Err(invalid());
            }
            if pins[..i].iter().any(|old| {
                old.image().instance_id() == pin.image().instance_id()
                    || old.image().key() == pin.image().key()
            }) {
                return Err(invalid());
            }
        }
        for (index, id) in global.iter().enumerate() {
            if global[..index].contains(id) || !pins.iter().any(|p| p.image().instance_id() == *id)
            {
                return Err(invalid());
            }
        }
        Ok(Self { pins, global })
    }
    pub fn empty() -> Self {
        Self {
            pins: Vec::new(),
            global: Vec::new(),
        }
    }
    pub fn images(&self) -> impl Iterator<Item = &ImageHandle> {
        self.pins.iter().map(ImagePin::image)
    }
    pub(crate) fn globals(&self) -> LoadResult<Vec<ImageHandle>> {
        let mut images = Vec::new();
        images
            .try_reserve_exact(self.global.len())
            .map_err(|_| oom())?;
        for id in &self.global {
            images.push(
                self.pins
                    .iter()
                    .find(|p| p.image().instance_id() == *id)
                    .ok_or_else(invalid)?
                    .image()
                    .clone(),
            );
        }
        Ok(images)
    }
}

#[derive(Clone, Debug)]
pub struct ImageCandidate {
    pub key: ImageKey,
    pub artifact: ArtifactId,
    pub managed: bool,
}
#[derive(Clone, Debug)]
pub struct ReservedImage {
    pub key: ImageKey,
    pub instance: ImageInstanceId,
}
/// Own all permits and imported pins of one atomic acquire. Drop cancels all
/// uncommitted permits, without callbacks. The lists remain stable until consumed
/// by the publisher; each requested key occurs in exactly one list.
pub trait LoadReservation {
    type Pin: ImagePin;
    fn reserved(&self) -> &[ReservedImage];
    fn imported(&self) -> &[Self::Pin];
}

/// Host policy for reuse and concurrency, separate from artifact lookup.
/// Discovery only pins existing instances. Acquire must reserve the entire new
/// closure atomically, waiting outside internal locks and returning no partial batch.
/// If a candidate became Ready concurrently, return its exact pin as an import.
pub trait ImageRepository {
    type Pin: ImagePin;
    type Reservation: LoadReservation<Pin = Self::Pin>;
    fn snapshot(&mut self, key: &ImageKey) -> LoadResult<Option<Self::Pin>>;
    /// Pin this exact generation or fail. Never reopen or re-resolve an artifact.
    fn pin_exact(&mut self, instance: &ImageInstanceId) -> LoadResult<Self::Pin>;
    fn acquire(&mut self, candidates: &[ImageCandidate]) -> LoadResult<Self::Reservation>;
}

/// A private-only repository for hosts without a shared-image registry.
#[derive(Default)]
pub struct LocalRepository;
/// No previously loaded provider can originate from LocalRepository.
#[must_use]
pub struct LocalPin(core::convert::Infallible);
unsafe impl ImagePin for LocalPin {
    fn image(&self) -> &ImageHandle {
        match self.0 {}
    }
}
#[must_use = "retain the reserved instance identities through publication"]
pub struct LocalReservation {
    images: Vec<ReservedImage>,
}
impl LoadReservation for LocalReservation {
    type Pin = LocalPin;
    fn reserved(&self) -> &[ReservedImage] {
        &self.images
    }
    fn imported(&self) -> &[LocalPin] {
        &[]
    }
}
impl ImageRepository for LocalRepository {
    type Pin = LocalPin;
    type Reservation = LocalReservation;
    fn snapshot(&mut self, _: &ImageKey) -> LoadResult<Option<LocalPin>> {
        Ok(None)
    }
    fn pin_exact(&mut self, _: &ImageInstanceId) -> LoadResult<LocalPin> {
        Err(invalid())
    }
    fn acquire(&mut self, candidates: &[ImageCandidate]) -> LoadResult<LocalReservation> {
        let mut images = Vec::new();
        images
            .try_reserve_exact(candidates.len())
            .map_err(|_| oom())?;
        for c in candidates {
            if c.managed {
                return Err(invalid());
            }
            images.push(ReservedImage {
                key: c.key.clone(),
                instance: ImageInstanceId::fresh()?,
            });
        }
        Ok(LocalReservation { images })
    }
}
