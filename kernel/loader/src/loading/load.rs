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

//! Complete load preparation and publication through separate host capabilities.
use super::{materialize::load_images, planning::LoadPlan, publication::CapturePublisher};
use crate::{
    dynamic_linker::prepare_link,
    error::{invalid, oom, ErrorContext, LoadErrorKind},
    image::ArtifactRole,
    memory::{CodeCache, ImageProtectionMemory},
    profile::{LoadProfile, SessionLimits},
    trace::{emit, trace_product, LoadEvent, LoadObserver, LoadPhase},
    ArtifactResolver, ImageCandidate, ImageHandle, ImagePin, ImageRepository, LoadError,
    LoadPublisher, LoadReservation, LoadResult, LoadedImage, NamespaceSnapshot, PreparedLoad,
    PublicationManifest,
};
use alloc::vec::Vec;

#[must_use = "submit the request or release its namespace pins"]
pub struct LoadRequest<S, P: ImagePin = super::repository::LocalPin> {
    pub(crate) source: S,
    pub(crate) profile: LoadProfile,
    pub(crate) limits: SessionLimits,
    pub(crate) role: ArtifactRole,
    pub(crate) namespace: NamespaceSnapshot<P>,
}
impl<S, P: ImagePin> LoadRequest<S, P> {
    pub fn executable(source: S, profile: LoadProfile, limits: SessionLimits) -> Self {
        Self::for_role(source, profile, limits, ArtifactRole::ExecutableRoot)
    }
    pub fn shared_object(source: S, profile: LoadProfile, limits: SessionLimits) -> Self {
        Self::for_role(source, profile, limits, ArtifactRole::SharedObject)
    }
    fn for_role(
        source: S,
        profile: LoadProfile,
        limits: SessionLimits,
        role: ArtifactRole,
    ) -> Self {
        Self {
            source,
            profile,
            limits,
            role,
            namespace: NamespaceSnapshot::empty(),
        }
    }
    pub fn with_namespace(mut self, namespace: NamespaceSnapshot<P>) -> Self {
        self.namespace = namespace;
        self
    }
}

/// Disjoint host capabilities. Memory moves into preparation and its final owner;
/// the remaining services are borrowed only for this operation.
pub struct LoadServices<'a, S, R, M, C, O> {
    pub sources: &'a mut S,
    pub images: &'a mut R,
    pub memory: M,
    pub cache: &'a mut C,
    pub observer: &'a mut O,
}

/// Discover, map, relocate and seal a closure without publishing or executing it.
/// The returned guard exposes a complete manifest and rolls back when dropped.
pub fn prepare_load<S, R, M, C, O>(
    request: LoadRequest<S::Source, R::Pin>,
    services: LoadServices<'_, S, R, M, C, O>,
) -> LoadResult<PreparedLoad<M, R::Pin, R::Reservation>>
where
    S: ArtifactResolver,
    R: ImageRepository,
    M: ImageProtectionMemory,
    C: CodeCache,
    O: LoadObserver,
{
    let LoadServices {
        sources,
        images,
        memory,
        cache,
        observer,
    } = services;
    emit(
        observer,
        LoadEvent::Started {
            path: sources.info(&request.source).key().identity(),
            executable: request.role == ArtifactRole::ExecutableRoot,
        },
    );
    let result = prepare_inner(
        request,
        LoadServices {
            sources,
            images,
            memory,
            cache,
            observer: &mut *observer,
        },
    );
    if let Err(error) = &result {
        emit(observer, LoadEvent::Failed { error });
    }
    result
}

/// Convenience entry combining preparation and ownership publication.
/// Completion means the owner adopted resources; constructors remain host-controlled.
pub fn load<S, R, M, C, O, U>(
    request: LoadRequest<S::Source, R::Pin>,
    services: LoadServices<'_, S, R, M, C, O>,
    publisher: &mut U,
) -> LoadResult<LoadedImage<U::Owner>>
where
    S: ArtifactResolver,
    R: ImageRepository,
    M: ImageProtectionMemory,
    C: CodeCache,
    O: LoadObserver,
    U: LoadPublisher<M, R::Pin, R::Reservation>,
{
    let LoadServices {
        sources,
        images,
        memory,
        cache,
        observer,
    } = services;
    let prepared = prepare_load(
        request,
        LoadServices {
            sources,
            images,
            memory,
            cache,
            observer: &mut *observer,
        },
    )?;
    phase(observer, LoadPhase::Publish, false);
    let result = prepared.publish(publisher);
    match &result {
        Ok(_) => {
            phase(observer, LoadPhase::Publish, true);
            emit(observer, LoadEvent::Completed);
        }
        Err(error) => emit(observer, LoadEvent::Failed { error }),
    }
    result
}
fn phase<O: LoadObserver + ?Sized>(observer: &mut O, phase: LoadPhase, completed: bool) {
    emit(observer, LoadEvent::Phase { phase, completed });
}
fn prepare_inner<S, R, M, C, O>(
    request: LoadRequest<S::Source, R::Pin>,
    services: LoadServices<'_, S, R, M, C, O>,
) -> LoadResult<PreparedLoad<M, R::Pin, R::Reservation>>
where
    S: ArtifactResolver,
    R: ImageRepository,
    M: ImageProtectionMemory,
    C: CodeCache,
    O: LoadObserver,
{
    let LoadServices {
        sources,
        images: repository,
        mut memory,
        cache,
        observer,
    } = services;
    let domain = memory.execution_domain();
    if cache.execution_domain() != domain {
        return Err(invalid());
    }
    for image in request.namespace.images() {
        validate_provider(image, request.profile, domain)?;
    }
    let mut pins = Vec::new();
    let (mut plan, reservation) = loop {
        phase(observer, LoadPhase::Discover, false);
        let plan = LoadPlan::build(&request, sources, repository, &mut pins, observer)?;
        for image in plan.snapshots() {
            validate_provider(image, request.profile, domain)?;
        }
        emit(
            observer,
            LoadEvent::Closure {
                images: plan.images.len(),
                dependencies: plan.edges.len(),
            },
        );
        phase(observer, LoadPhase::Discover, true);
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(plan.images.len())
            .map_err(|_| oom())?;
        for image in &plan.images {
            if image.snapshot.is_none() {
                candidates.push(ImageCandidate {
                    key: image.info.key().clone(),
                    artifact: image.artifact,
                    managed: image.shared,
                });
            }
        }
        phase(observer, LoadPhase::Acquire, false);
        let reservation = repository.acquire(&candidates)?;
        phase(observer, LoadPhase::Acquire, true);
        // Every candidate is either imported or reserved exactly once; the host
        // cannot substitute an unrelated key or alias two mapping identities.
        for candidate in &candidates {
            let imports = reservation
                .imported()
                .iter()
                .filter(|p| p.image().key() == &candidate.key)
                .count();
            let slots = reservation
                .reserved()
                .iter()
                .filter(|s| s.key == candidate.key)
                .count();
            if imports + slots != 1 {
                return Err(invalid());
            }
        }
        for (index, pin) in reservation.imported().iter().enumerate() {
            let image = pin.image();
            if !candidates
                .iter()
                .any(|c| &c.key == image.key() && c.managed == image.is_shared())
                || reservation.imported()[..index]
                    .iter()
                    .any(|p| p.image().instance_id() == image.instance_id())
            {
                return Err(invalid());
            }
        }
        let mut matches = true;
        for pin in reservation.imported() {
            let image = pin.image();
            validate_provider(image, request.profile, domain)?;
            if !plan.images.iter().any(|p| p.info.key() == image.key()) {
                return Err(invalid());
            }
            matches &= plan.matches_snapshot(image);
        }
        if matches {
            break (plan, reservation);
        }
        drop(reservation);
        pins.clear();
        emit(observer, LoadEvent::Retry);
    };
    for image in &mut plan.images {
        if image.snapshot.is_none() {
            if let Some(pin) = reservation
                .imported()
                .iter()
                .find(|p| p.image().key() == image.info.key())
            {
                image.instance = Some(pin.image().instance_id());
            } else {
                let selected = reservation
                    .reserved()
                    .iter()
                    .find(|r| &r.key == image.info.key())
                    .ok_or_else(invalid)?;
                image.instance = Some(selected.instance);
            }
        }
    }
    // The acquired batch cannot introduce duplicate or unrequested identities.
    for (i, slot) in reservation.reserved().iter().enumerate() {
        if !plan
            .images
            .iter()
            .any(|p| p.info.key() == &slot.key && p.snapshot.is_none())
            || reservation.reserved()[..i]
                .iter()
                .any(|old| old.key == slot.key || old.instance == slot.instance)
        {
            return Err(invalid());
        }
    }
    for (index, image) in plan.images.iter().enumerate() {
        if plan.images[..index]
            .iter()
            .any(|old| old.instance == image.instance)
        {
            return Err(invalid());
        }
    }
    // One session cannot silently merge two generations or namespace keys behind
    // the same ELF graph identity, including providers supplied only through globals.
    for planned in &plan.images {
        for pin in request
            .namespace
            .pins
            .iter()
            .chain(pins.iter())
            .chain(reservation.imported().iter())
        {
            let image = pin.image();
            if planned.identity.as_bytes() == image.identity()
                && (planned.info.key() != image.key()
                    || planned.instance != Some(image.instance_id()))
            {
                return Err(invalid());
            }
        }
    }
    let mut providers = Vec::new();
    providers
        .try_reserve_exact(request.namespace.pins.len() + pins.len() + reservation.imported().len())
        .map_err(|_| oom())?;
    for pin in request
        .namespace
        .pins
        .iter()
        .chain(pins.iter())
        .chain(reservation.imported().iter())
    {
        if !providers
            .iter()
            .any(|p: &ImageHandle| p.instance_id() == pin.image().instance_id())
        {
            providers.push(pin.image().clone());
        }
    }
    let globals = request.namespace.globals()?;
    phase(observer, LoadPhase::Map, false);
    let images = load_images(
        &mut plan,
        &providers,
        &globals,
        request.profile,
        request.limits,
        &mut memory,
        |e| emit(observer, e),
    )?;
    phase(observer, LoadPhase::Map, true);
    phase(observer, LoadPhase::Link, false);
    let sealed = prepare_link(images, cache)?;
    phase(observer, LoadPhase::Link, true);
    let mut capture = CapturePublisher::new(&plan);
    let mut product = sealed.publish(&mut capture)?;
    let entry = (request.role == ArtifactRole::ExecutableRoot).then(|| product.entry());
    // No fallible work occurs between disarming the internal log and arming this owning rollback guard.
    let mut prepared = PreparedLoad {
        memory: Some(memory),
        allocations: Vec::new(),
        pins,
        reservation: Some(reservation),
        manifest: None,
    };
    prepared.allocations = product.take_publication();
    trace_product(observer, &product);
    let mut facts = capture.facts.take().expect("capture prepared facts");
    facts.entry = entry;
    let mut allocations = Vec::new();
    allocations
        .try_reserve_exact(prepared.allocations.len())
        .map_err(|_| oom())?;
    for (image, lease) in &prepared.allocations {
        allocations.push((image.clone(), *lease.allocation()));
    }
    prepared
        .pins
        .try_reserve(request.namespace.pins.len())
        .map_err(|_| oom())?;
    for pin in request.namespace.pins {
        if facts
            .retained
            .iter()
            .any(|i| i.instance_id() == pin.image().instance_id())
        {
            prepared.pins.push(pin);
        }
    }
    prepared.manifest = Some(PublicationManifest {
        image: LoadedImage::new((), facts),
        allocations,
    });
    Ok(prepared)
}
fn validate_provider(
    image: &ImageHandle,
    profile: LoadProfile,
    domain: crate::ExecutionDomainId,
) -> LoadResult<()> {
    if image.descriptor.snapshot().profile() != profile || image.execution_domain() != domain {
        return Err(LoadError::new(
            LoadErrorKind::UnsupportedByProfile,
            ErrorContext::None,
        ));
    }
    Ok(())
}
