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

//! Load requests and orchestration of discovery, linking, publication and installation.

use alloc::vec::Vec;

use crate::{
    dynamic_linker::{ArtifactRole, DependencyResolution},
    error::{invalid, oom, ErrorContext, LoadErrorKind},
    linker::{prepare_link, LinkRequest},
    planning::{LoadPlan, PlannedResolver},
    profile::{LoadProfile, SessionLimits},
    publication::BackendPublisher,
    trace::{emit, trace_product, LoadEvent, LoadPhase},
    ImageHandle, LoadError, LoadResult, LoadedImage, LoaderBackend,
};

/// Load inputs with an explicit purpose. ELF contents determine placement and
/// dependencies; a shared object is never inferred from its entry or ownership.
pub struct LoadRequest<S> {
    pub(crate) source: S,
    pub(crate) profile: LoadProfile,
    pub(crate) limits: SessionLimits,
    pub(crate) role: ArtifactRole,
    pub(crate) existing: Vec<ImageHandle>,
    pub(crate) global: Vec<ImageHandle>,
}

impl<S> LoadRequest<S> {
    /// Load a fresh executable (ET_EXEC or PIE) and validate its runtime entry.
    pub fn executable(source: S, profile: LoadProfile, limits: SessionLimits) -> Self {
        Self::for_role(source, profile, limits, ArtifactRole::ExecutableRoot)
    }
    /// Load or reuse an ET_DYN shared object. ET_EXEC and DF_1_PIE are rejected,
    /// and a nonzero entry does not turn the object into an executable launch.
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
            existing: Vec::new(),
            global: Vec::new(),
        }
    }
    /// Supply pinned existing images and the ordered global symbol prefix.
    /// Keep them pinned through installation; `retained_images` identifies
    /// which previous owners the new result still needs.
    pub fn with_namespace(mut self, existing: Vec<ImageHandle>, global: Vec<ImageHandle>) -> Self {
        self.existing = existing;
        self.global = global;
        self
    }
}

/// Load, link and publish the full dependency closure through platform services.
///
/// Scanning, dependency graphs, symbol scopes and retention calculations stay
/// inside the loader. Every new allocation is rolled back on pre-commit failure;
/// a completion failure returns the receipt to the backend for release.
pub fn load<B: LoaderBackend>(
    request: LoadRequest<B::Source>,
    backend: &mut B,
) -> LoadResult<LoadedImage<B::Receipt>> {
    emit(
        backend,
        LoadEvent::Started {
            path: backend.identity(&request.source),
            executable: request.role == ArtifactRole::ExecutableRoot,
        },
    );
    let result = load_inner(request, backend);
    match &result {
        Ok(_) => emit(backend, LoadEvent::Completed),
        Err(error) => {
            backend.cancel_load();
            emit(backend, LoadEvent::Failed { error });
        }
    }
    result
}

fn phase<B: LoaderBackend>(backend: &B, phase: LoadPhase, completed: bool) {
    emit(backend, LoadEvent::Phase { phase, completed });
}

fn load_inner<B: LoaderBackend>(
    request: LoadRequest<B::Source>,
    backend: &mut B,
) -> LoadResult<LoadedImage<B::Receipt>> {
    for image in request.existing.iter().chain(&request.global) {
        if image.descriptor.snapshot().profile() != request.profile {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            ));
        }
    }
    let (mut plan, ready) = loop {
        phase(backend, LoadPhase::Discover, false);
        let plan = LoadPlan::build(&request, backend)?;
        emit(
            backend,
            LoadEvent::Closure {
                images: plan.images.len(),
                dependencies: plan.edges.len(),
            },
        );
        phase(backend, LoadPhase::Discover, true);
        let sources = plan
            .images
            .iter()
            .map(|image| image.source.clone())
            .collect::<Vec<_>>();
        phase(backend, LoadPhase::Acquire, false);
        let ready = backend.acquire(&sources, &request.existing)?;
        phase(backend, LoadPhase::Acquire, true);
        for image in &ready {
            if image.descriptor.snapshot().profile() != request.profile {
                return Err(LoadError::new(
                    LoadErrorKind::UnsupportedByProfile,
                    ErrorContext::None,
                ));
            }
            if !plan.contains(image.identity())
                || (request.role == ArtifactRole::ExecutableRoot
                    && image.identity() == plan.images[0].identity.as_bytes())
            {
                return Err(invalid());
            }
        }
        if ready.iter().all(|image| plan.matches_snapshot(image)) {
            break (plan, ready);
        }
        // A concurrent publisher may win after a vacant source was scanned.
        // Release this whole reservation before planning its frozen closure;
        // never enlarge a batch while holding partial load permits.
        backend.cancel_load();
        emit(backend, LoadEvent::Retry);
    };
    let mut providers = request.existing;
    providers
        .try_reserve(plan.images.len() + ready.len())
        .map_err(|_| oom())?;
    for image in plan.snapshots().cloned().chain(ready) {
        if !providers
            .iter()
            .any(|provider| provider.identity() == image.identity())
        {
            providers.push(image);
        }
    }
    let dependencies = providers
        .iter()
        .filter(|image| plan.contains(image.identity()))
        .map(ImageHandle::imported)
        .collect();
    let globals = request.global.iter().map(ImageHandle::imported).collect();
    let connections = plan.connections()?;
    phase(backend, LoadPhase::Link, false);
    let mut memory = backend.memory();
    let mut resolver = PlannedResolver {
        plan: &mut plan,
        backend,
        providers: &providers,
    };
    let role = resolver.plan.images[0].scanned.role;
    let root = match role {
        ArtifactRole::ExecutableRoot => DependencyResolution::Load(resolver.load_root()?),
        ArtifactRole::SharedObject => resolver.resolve_index(0)?,
    };
    let request = LinkRequest::new(root, role, request.profile, request.limits).with_namespace(
        globals,
        dependencies,
        connections,
    );
    let prepared = prepare_link(request, &mut resolver, &mut memory)?;
    phase(backend, LoadPhase::Link, true);
    let mut publisher = BackendPublisher::new(backend, &plan);
    phase(publisher.backend, LoadPhase::Publish, false);
    let product = prepared.publish(&mut publisher)?;
    phase(publisher.backend, LoadPhase::Publish, true);
    let mut facts = publisher
        .facts
        .take()
        .expect("publication prepared result metadata");
    facts.entry = (plan.images[0].scanned.role
        == crate::dynamic_linker::ArtifactRole::ExecutableRoot)
        .then(|| product.entry());
    trace_product(publisher.backend, &product);
    let mut loaded = LoadedImage::new(product.into_publication(), facts);
    phase(publisher.backend, LoadPhase::Install, false);
    if let Err(error) = publisher.backend.complete_load(&mut loaded) {
        publisher.backend.abort_publication(loaded.into_receipt());
        return Err(error);
    }
    phase(publisher.backend, LoadPhase::Install, true);
    Ok(loaded)
}
