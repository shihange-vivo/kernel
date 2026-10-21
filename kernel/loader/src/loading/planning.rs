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

//! Discover the complete dependency closure before reserving new instances.
use crate::{
    dynamic_linker::ArtifactIdentity,
    error::{invalid, oom, overflow, ErrorContext, LoadErrorKind},
    image::{ArtifactRole, DependencyName, ScannedArtifact},
    trace::{emit, LoadEvent, LoadObserver},
    ArtifactId, ArtifactInfo, ArtifactResolver, ImageHandle, ImageInstanceId, ImagePin,
    ImageRepository, LoadRequest, LoadResult,
};
use alloc::vec::Vec;

pub(crate) struct PlannedImage<S, R> {
    pub(crate) source: Option<S>,
    pub(crate) identity: ArtifactIdentity,
    pub(crate) info: ArtifactInfo,
    pub(crate) shared: bool,
    pub(crate) instance: Option<ImageInstanceId>,
    pub(crate) artifact: ArtifactId,
    pub(crate) reader: Option<R>,
    pub(crate) snapshot: Option<ImageHandle>,
    pub(crate) scanned: ScannedArtifact,
}
pub(crate) struct PlannedEdge {
    pub(crate) requester: usize,
    pub(crate) provider: usize,
    pub(crate) needed_index: u16,
}
pub(crate) struct LoadPlan<S, R> {
    pub(crate) images: Vec<PlannedImage<S, R>>,
    pub(crate) edges: Vec<PlannedEdge>,
}
impl<S, R> LoadPlan<S, R> {
    pub(crate) fn snapshots(&self) -> impl Iterator<Item = &ImageHandle> {
        self.images.iter().filter_map(|i| i.snapshot.as_ref())
    }
    pub(crate) fn matches_snapshot(&self, image: &ImageHandle) -> bool {
        let Some(index) = self.images.iter().position(|p| p.info.key() == image.key()) else {
            return false;
        };
        let p = &self.images[index];
        p.shared == image.is_shared()
            && p.scanned.role == image.descriptor.snapshot().role()
            && p.scanned.declared_soname.as_ref() == image.descriptor.soname()
            && p.scanned.needed.len() == image.dependencies().len()
            && image
                .dependencies()
                .iter()
                .enumerate()
                .all(|(needed_index, d)| {
                    p.scanned.needed[needed_index].as_bytes() == d.name()
                        && self.edges.iter().any(|e| {
                            e.requester == index
                                && e.needed_index as usize == needed_index
                                && self.images[e.provider].instance == Some(d.instance_id())
                        })
                })
    }
    pub(crate) fn metadata_bytes(&self) -> LoadResult<u64> {
        let mut bytes = core::mem::size_of::<Self>() as u64
            + (self.images.capacity() * core::mem::size_of::<PlannedImage<S, R>>()) as u64
            + (self.edges.capacity() * core::mem::size_of::<PlannedEdge>()) as u64;
        for i in &self.images {
            let names = i
                .scanned
                .needed
                .iter()
                .map(|n| n.as_bytes().len() as u64)
                .sum::<u64>();
            bytes = bytes
                .checked_add(
                    i.identity.metadata_bytes()
                        + names
                        + (i.scanned.needed.capacity() * core::mem::size_of::<DependencyName>())
                            as u64
                        + i.scanned
                            .declared_soname
                            .as_ref()
                            .map_or(0, |n| n.as_bytes().len() as u64)
                        + i.info.key().identity().len() as u64,
                )
                .ok_or_else(overflow)?;
        }
        Ok(bytes)
    }
}

impl<S: Clone, R: crate::reader::ElfReader> LoadPlan<S, R> {
    pub(crate) fn build<A, I, O>(
        request: &LoadRequest<S, I::Pin>,
        sources: &mut A,
        repository: &mut I,
        pins: &mut Vec<I::Pin>,
        observer: &mut O,
    ) -> LoadResult<Self>
    where
        A: ArtifactResolver<Source = S, Reader = R>,
        I: ImageRepository,
        O: LoadObserver + ?Sized,
    {
        if request.role == ArtifactRole::ExecutableRoot
            && sources.info(&request.source).is_managed()
        {
            return Err(unsupported());
        }
        request.limits.check_image_count(1)?;
        let root = scan_source(
            request.source.clone(),
            request.role,
            request,
            sources,
            repository,
            pins,
            observer,
        )?;
        let mut plan = Self {
            images: Vec::new(),
            edges: Vec::new(),
        };
        plan.images.try_reserve(1).map_err(|_| oom())?;
        plan.images.push(root);
        let mut queue = Vec::new();
        queue.try_reserve(1).map_err(|_| oom())?;
        queue.push((0, 1u16));
        let mut input_bytes = plan.images[0]
            .reader
            .as_ref()
            .map(crate::reader::ElfReader::len)
            .transpose()?
            .unwrap_or(0);
        request.limits.check_total_input_bytes(input_bytes)?;
        let mut cursor = 0;
        while cursor < queue.len() {
            let (requester, depth) = queue[cursor];
            cursor += 1;
            let mut needed = Vec::new();
            needed
                .try_reserve_exact(plan.images[requester].scanned.needed.len())
                .map_err(|_| oom())?;
            for name in &plan.images[requester].scanned.needed {
                needed.push(name.try_clone()?);
            }
            for (needed_index, name) in needed.into_iter().enumerate() {
                request
                    .limits
                    .check_dependency_name_len(name.as_bytes().len() as u32)?;
                request
                    .limits
                    .check_dependency_edge_count((plan.edges.len() + 1) as u32)?;
                let frozen = plan.images[requester]
                    .snapshot
                    .as_ref()
                    .map(|i| &i.dependencies()[needed_index]);
                let reuse_required = frozen.is_some();
                let image = if let Some(dependency) = frozen {
                    let id = dependency.instance_id();
                    let snapshot = if let Some(p) = request
                        .namespace
                        .pins
                        .iter()
                        .chain(pins.iter())
                        .find(|p| p.image().instance_id() == id)
                    {
                        p.image().clone()
                    } else {
                        let pin = repository.pin_exact(&id)?;
                        if pin.image().instance_id() != id {
                            return Err(invalid());
                        }
                        let snapshot = pin.image().clone();
                        pins.try_reserve(1).map_err(|_| oom())?;
                        pins.push(pin);
                        snapshot
                    };
                    if snapshot.identity() != dependency.identity()
                        || snapshot.is_shared() != dependency.is_shared()
                    {
                        return Err(invalid());
                    }
                    scan_snapshot(None, snapshot, request, observer)?
                } else {
                    let source = plan.images[requester].source.as_ref().ok_or_else(invalid)?;
                    let selected = sources.resolve(source, name.as_bytes())?;
                    let info = sources.info(&selected);
                    if let Some(index) = plan.images.iter().position(|i| i.info.key() == info.key())
                    {
                        let provider = index;
                        if plan.images[provider].scanned.role != ArtifactRole::SharedObject {
                            return Err(unsupported());
                        }
                        plan.edges.try_reserve(1).map_err(|_| oom())?;
                        plan.edges.push(PlannedEdge {
                            requester,
                            provider,
                            needed_index: u16::try_from(needed_index).map_err(|_| overflow())?,
                        });
                        emit(
                            observer,
                            LoadEvent::Dependency {
                                requester: plan.images[requester].identity.as_bytes(),
                                name: name.as_bytes(),
                                provider: plan.images[provider].identity.as_bytes(),
                                frozen: false,
                            },
                        );
                        continue;
                    }
                    scan_source(
                        selected,
                        ArtifactRole::SharedObject,
                        request,
                        sources,
                        repository,
                        pins,
                        observer,
                    )?
                };
                let provider = if let Some(index) = plan
                    .images
                    .iter()
                    .position(|i| i.info.key() == image.info.key())
                {
                    if plan.images[index].scanned.role != ArtifactRole::SharedObject
                        || (reuse_required && plan.images[index].instance != image.instance)
                    {
                        return Err(invalid());
                    }
                    index
                } else {
                    // The internal ELF graph uses byte identities. Reject ambiguous keys rather than merging namespaces.
                    if plan.images.iter().any(|i| i.identity == image.identity) {
                        return Err(invalid());
                    }
                    request
                        .limits
                        .check_image_count((plan.images.len() + 1) as u32)?;
                    let next = depth.checked_add(1).ok_or_else(overflow)?;
                    request.limits.check_dependency_depth(next)?;
                    plan.images.try_reserve(1).map_err(|_| oom())?;
                    queue.try_reserve(1).map_err(|_| oom())?;
                    input_bytes = input_bytes
                        .checked_add(
                            image
                                .reader
                                .as_ref()
                                .map(crate::reader::ElfReader::len)
                                .transpose()?
                                .unwrap_or(0),
                        )
                        .ok_or_else(overflow)?;
                    request.limits.check_total_input_bytes(input_bytes)?;
                    let index = plan.images.len();
                    plan.images.push(image);
                    queue.push((index, next));
                    index
                };
                plan.edges.try_reserve(1).map_err(|_| oom())?;
                plan.edges.push(PlannedEdge {
                    requester,
                    provider,
                    needed_index: u16::try_from(needed_index).map_err(|_| overflow())?,
                });
                emit(
                    observer,
                    LoadEvent::Dependency {
                        requester: plan.images[requester].identity.as_bytes(),
                        name: name.as_bytes(),
                        provider: plan.images[provider].identity.as_bytes(),
                        frozen: reuse_required,
                    },
                );
            }
        }
        request.limits.check_image_count(plan.images.len() as u32)?;
        request
            .limits
            .check_total_runtime_metadata_bytes(plan.metadata_bytes()?)?;
        Ok(plan)
    }
}
fn scan_source<A: ArtifactResolver, I: ImageRepository, O: LoadObserver + ?Sized>(
    source: A::Source,
    role: ArtifactRole,
    request: &LoadRequest<A::Source, I::Pin>,
    sources: &mut A,
    repository: &mut I,
    pins: &mut Vec<I::Pin>,
    observer: &mut O,
) -> LoadResult<PlannedImage<A::Source, A::Reader>> {
    let info = sources.info(&source).clone();
    if role == ArtifactRole::SharedObject {
        let snapshot = if let Some(p) = request
            .namespace
            .pins
            .iter()
            .chain(pins.iter())
            .find(|p| p.image().key() == info.key())
        {
            Some(p.image().clone())
        } else if let Some(pin) = repository.snapshot(info.key())? {
            if pin.image().key() != info.key() {
                return Err(invalid());
            }
            let image = pin.image().clone();
            pins.try_reserve(1).map_err(|_| oom())?;
            pins.push(pin);
            Some(image)
        } else {
            None
        };
        if let Some(snapshot) = snapshot {
            if snapshot.is_shared() != info.is_managed() {
                return Err(invalid());
            }
            return scan_snapshot(Some(source), snapshot, request, observer);
        }
    }
    let opened = sources.open(&source)?;
    let scanned = crate::image::scan::scan_root_or_dependency(
        opened.reader(),
        request.profile,
        role,
        *request.limits.per_image(),
    )?;
    let identity = ArtifactIdentity::from_bytes(info.key().identity())?;
    let shared = info.is_managed();
    emit(
        observer,
        LoadEvent::Inspected {
            path: identity.as_bytes(),
            system: shared,
            snapshot: false,
        },
    );
    Ok(PlannedImage {
        source: Some(source),
        identity,
        info,
        shared,
        instance: None,
        artifact: opened.artifact,
        reader: Some(opened.reader),
        snapshot: None,
        scanned,
    })
}
fn scan_snapshot<S, R, P: ImagePin, O: LoadObserver + ?Sized>(
    source: Option<S>,
    snapshot: ImageHandle,
    request: &LoadRequest<S, P>,
    observer: &mut O,
) -> LoadResult<PlannedImage<S, R>> {
    let published = snapshot.descriptor.snapshot();
    if published.profile() != request.profile || published.role() != ArtifactRole::SharedObject {
        return Err(unsupported());
    }
    let mut needed = Vec::new();
    needed
        .try_reserve_exact(snapshot.dependencies().len())
        .map_err(|_| oom())?;
    for d in snapshot.dependencies() {
        request
            .limits
            .check_dependency_name_len(d.name().len() as u32)?;
        needed.push(d.needed().try_clone()?);
    }
    let scanned = ScannedArtifact {
        role: ArtifactRole::SharedObject,
        declared_soname: snapshot
            .descriptor
            .soname()
            .map(DependencyName::try_clone)
            .transpose()?,
        needed,
    };
    let identity = ArtifactIdentity::from_bytes(snapshot.identity())?;
    let shared = snapshot.is_shared();
    emit(
        observer,
        LoadEvent::Inspected {
            path: identity.as_bytes(),
            system: shared,
            snapshot: true,
        },
    );
    Ok(PlannedImage {
        source,
        identity,
        info: ArtifactInfo::new(snapshot.key().clone(), shared),
        shared,
        instance: Some(snapshot.instance_id()),
        artifact: snapshot.artifact_id(),
        reader: None,
        snapshot: Some(snapshot),
        scanned,
    })
}
fn unsupported() -> crate::LoadError {
    crate::LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
}
