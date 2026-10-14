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

//! Map the pre-acquired load plan once, preserving its ordered dependency edges.
//! The linker receives decoded images and a complete graph, never file readers.

use alloc::vec::Vec;

use super::planning::{LoadPlan, PlannedImage};
use crate::{
    dynamic_linker::{
        ArtifactIdentity, DependencyGraph, ImageId, ImageOwnership, ImportedImage, LinkSession,
        LoadedSession, LoadedState, PublishedImageDescriptor, PublishedRegion, SessionImage,
        SessionUsage,
    },
    elf::LoadSegmentInfo,
    error::{invalid, oom, overflow, ErrorContext, LoadErrorKind, LoadStage},
    image::{
        absorb_into_session, ArtifactRole, DependencyName, ImageLoader, LoadedRegion,
        RuntimeImageState,
    },
    memory::{AllocationRollbackGuard, AllocationRollbackLog, ImageMemory},
    profile::{LoadProfile, SessionLimits},
    reader::ElfReader,
    relocation::{ArchRelocator, NativeRelocator},
    trace::LoadEvent,
    ImageHandle, LoadError, LoadResult,
};

pub(crate) fn load_images<'m, S, R: ElfReader, M: ImageMemory + ?Sized>(
    plan: &mut LoadPlan<S, R>,
    providers: &[ImageHandle],
    globals: &[ImageHandle],
    profile: LoadProfile,
    limits: SessionLimits,
    memory: &'m mut M,
    mut observe: impl FnMut(LoadEvent<'_>),
) -> LoadResult<LoadedSession<'m, M, NativeRelocator>> {
    if NativeRelocator.machine() != profile.machine() || NativeRelocator.class() != profile.class()
    {
        return Err(
            LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
                .at_stage(LoadStage::Beginning),
        );
    }
    let mut session = LinkSession {
        rollback: AllocationRollbackGuard {
            memory,
            log: AllocationRollbackLog::new(),
        },
        graph: DependencyGraph::new(limits),
        limits,
        usage: SessionUsage::default(),
        profile,
        arch: NativeRelocator,
        state: LoadedState {
            images: Vec::new(),
            imported: Vec::new(),
            scope_prefix: Vec::new(),
        },
    };
    let mut ids = Vec::new();
    ids.try_reserve_exact(plan.images.len())
        .map_err(|_| oom())?;
    ids.resize(plan.images.len(), None);
    let root = plan.images.first_mut().ok_or_else(invalid)?;
    let provider = providers
        .iter()
        .find(|image| image.identity() == root.identity.as_bytes());
    ids[0] = Some(
        load_image(&mut session, root, provider, None, &mut observe)
            .map_err(|error| error.at_stage(LoadStage::Beginning))?,
    );

    for image in globals {
        let id = import_global(&mut session, image)?;
        if !session.state.scope_prefix.contains(&id) {
            session
                .state
                .scope_prefix
                .try_reserve(1)
                .map_err(|_| oom())?;
            session.state.scope_prefix.push(id);
        }
    }
    // The planner already traversed DT_NEEDED. Follow those edges directly;
    // mapping must not discover another file or enlarge the acquired closure.
    for edge in &plan.edges {
        let requester = ids[edge.requester].ok_or_else(invalid)?;
        if let Some(provider) = ids[edge.provider] {
            session
                .graph
                .link_existing(requester, provider, edge.needed_index)?;
            continue;
        }
        let needed = plan.images[edge.requester].scanned.needed[usize::from(edge.needed_index)]
            .try_clone()?;
        let image = &mut plan.images[edge.provider];
        let id = if let Some(id) = session.graph.find_identity(&image.identity) {
            session
                .graph
                .link_existing(requester, id, edge.needed_index)?;
            observe(LoadEvent::ImageReused {
                path: image.identity.as_bytes(),
                system: image.shared,
            });
            id
        } else {
            let provider = providers
                .iter()
                .find(|provider| provider.identity() == image.identity.as_bytes());
            load_image(
                &mut session,
                image,
                provider,
                Some((requester, &needed, edge.needed_index)),
                &mut observe,
            )
            .map_err(|error| error.at_stage(LoadStage::Discover))?
        };
        ids[edge.provider] = Some(id);
    }
    if ids.iter().any(Option::is_none) {
        return Err(invalid());
    }
    Ok(session)
}

fn insert_node<S, R, M: ImageMemory + ?Sized>(
    session: &mut LoadedSession<'_, M, NativeRelocator>,
    image: &PlannedImage<S, R>,
    ownership: ImageOwnership,
    soname: Option<DependencyName>,
    parent: Option<(ImageId, &DependencyName, u16)>,
) -> LoadResult<ImageId> {
    let identity = image.identity.try_clone()?;
    match parent {
        Some((requester, needed, index)) => session
            .graph
            .insert_dependency(requester, needed, index, identity, soname, ownership),
        None => session.graph.insert_root(identity, soname, ownership),
    }
}

fn load_image<S, R: ElfReader, M: ImageMemory + ?Sized>(
    session: &mut LoadedSession<'_, M, NativeRelocator>,
    image: &mut PlannedImage<S, R>,
    provider: Option<&ImageHandle>,
    parent: Option<(ImageId, &DependencyName, u16)>,
    observe: &mut impl FnMut(LoadEvent<'_>),
) -> LoadResult<ImageId> {
    if let Some(provider) = provider {
        if image.scanned.role == ArtifactRole::ExecutableRoot {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            ));
        }
        let (descriptor, ownership) = provider.imported().into_parts();
        session
            .usage
            .record_image(0, imported_metadata_bytes(&descriptor)?, &session.limits)?;
        session.state.imported.try_reserve(1).map_err(|_| oom())?;
        let id = insert_node(
            session,
            image,
            ownership,
            descriptor
                .soname()
                .map(DependencyName::try_clone)
                .transpose()?,
            parent,
        )?;
        session.state.imported.push(ImportedImage {
            image_id: id,
            descriptor,
        });
        observe(LoadEvent::ImageReused {
            path: image.identity.as_bytes(),
            system: image.shared,
        });
        return Ok(id);
    }
    let reader = image.reader.take().ok_or_else(invalid)?;
    observe(LoadEvent::ImageLoadStarted {
        path: image.identity.as_bytes(),
        system: image.shared,
    });
    let decoded = ImageLoader::new(
        reader,
        crate::profile::LoadRequest::new(session.profile, *session.limits.per_image()),
    )
    .admit()?
    .with_role(image.scanned.role)
    .inspect()?
    .plan()?
    .allocate(&mut *session.rollback.memory)?
    .map()?
    .decode()?;
    let (allocation, mut runtime) = absorb_into_session(decoded, &mut session.rollback.log)?;
    let soname = runtime.take_soname();
    // Revalidate the original scan after mapping, including order and count.
    // A changed file must not silently add, remove or redirect dependencies.
    if runtime.metadata().needed() != image.scanned.needed.as_slice()
        || soname.as_ref() != image.scanned.declared_soname.as_ref()
    {
        return Err(LoadError::new(LoadErrorKind::BadElf, ErrorContext::None));
    }
    validate_session_symbol_names(&runtime, &session.limits)?;
    session.usage.record_image(
        allocation.allocation().len(),
        session_image_metadata_bytes(&runtime, &image.identity, soname.as_ref())?,
        &session.limits,
    )?;
    session.state.images.try_reserve(1).map_err(|_| oom())?;
    let ownership = if image.shared {
        ImageOwnership::SystemCandidate
    } else {
        ImageOwnership::SessionPrivate
    };
    let id = insert_node(session, image, ownership, soname, parent)?;
    session.state.images.push(SessionImage {
        image_id: id,
        role: image.scanned.role,
        allocation,
        state: runtime,
    });
    Ok(id)
}

fn import_global<M: ImageMemory + ?Sized>(
    session: &mut LoadedSession<'_, M, NativeRelocator>,
    image: &ImageHandle,
) -> LoadResult<ImageId> {
    let (descriptor, ownership) = image.imported().into_parts();
    if let Some(id) = session.graph.find_identity(descriptor.identity()) {
        return Ok(id);
    }
    session
        .usage
        .record_image(0, imported_metadata_bytes(&descriptor)?, &session.limits)?;
    session.state.imported.try_reserve(1).map_err(|_| oom())?;
    let id = session.graph.insert_scope_provider(
        descriptor.identity().try_clone()?,
        descriptor
            .soname()
            .map(DependencyName::try_clone)
            .transpose()?,
        ownership,
    )?;
    session.state.imported.push(ImportedImage {
        image_id: id,
        descriptor,
    });
    Ok(id)
}

fn validate_session_symbol_names(
    runtime: &RuntimeImageState,
    limits: &SessionLimits,
) -> LoadResult<()> {
    for entry in runtime.metadata().symbols().entries() {
        let len = u32::try_from(runtime.metadata().symbols().name(entry).len())
            .map_err(|_| LoadError::new(LoadErrorKind::ResourceLimit, ErrorContext::None))?;
        limits.check_symbol_name_len(len)?;
    }
    Ok(())
}

fn session_image_metadata_bytes(
    runtime: &RuntimeImageState,
    identity: &ArtifactIdentity,
    soname: Option<&DependencyName>,
) -> LoadResult<u64> {
    runtime
        .metadata()
        .metadata_bytes()
        .checked_add(identity.metadata_bytes())
        .and_then(|bytes| bytes.checked_add(soname.map_or(0, |name| name.as_bytes().len() as u64)))
        .and_then(|bytes| {
            bytes.checked_add(
                runtime.load_segments().len() as u64
                    * core::mem::size_of::<LoadSegmentInfo>() as u64,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                runtime.regions().len() as u64 * core::mem::size_of::<LoadedRegion>() as u64,
            )
        })
        .ok_or_else(overflow)
}

/// The retained runtime metadata bytes an imported Ready image keeps in the
/// session: its frozen export surface, its identity/SONAME copy, and its
/// published regions. Charged against
/// `SessionLimits::total_runtime_metadata_bytes` on import.
fn imported_metadata_bytes(descriptor: &PublishedImageDescriptor) -> LoadResult<u64> {
    descriptor
        .exports()
        .metadata_bytes()
        .checked_add(descriptor.identity().metadata_bytes())
        .and_then(|bytes| bytes.checked_add(descriptor.snapshot().metadata_bytes()))
        .and_then(|bytes| {
            bytes.checked_add(
                descriptor
                    .soname()
                    .map_or(0, |name| name.as_bytes().len() as u64),
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                descriptor.regions().len() as u64 * core::mem::size_of::<PublishedRegion>() as u64,
            )
        })
        .ok_or_else(overflow)
}
