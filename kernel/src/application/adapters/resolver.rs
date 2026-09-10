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

//! Runtime namespace resolver.
//!
//! The launch planner has already resolved every `DT_NEEDED` string to an
//! exact VFS path and acquired the complete system closure atomically. This
//! adapter therefore performs no search and takes no new system permit while
//! the linker owns mapped memory: it only replays planned requester/edge
//! bindings, reopens the frozen snapshots, and consumes the prepared permits
//! or leases.

use alloc::vec::Vec;

use blueos_loader::{
    ArtifactIdentity, ArtifactResolver, BuildId, DependencyName, DependencyRequest,
    DependencyResolution, ErrorContext, FileIdentity, ImageOwnership, ImportedImageDescriptor,
    LinkDomainId, LoadError, LoadErrorKind, LoadResult, ResolvedArtifact,
};

use crate::{
    application::{
        planner::{NamespaceLoadPlan, PlannedImage},
        registry::{
            AcquireBatchOutcome, LoadPermit, PreparedSystemBatch, SystemDsoLease, SystemDsoRegistry,
        },
    },
    vfs::{open_path, FileSnapshotId},
};

use super::vfs_reader::VfsElfReader;

struct SystemCandidateClaim {
    key: DependencyName,
    identity: ArtifactIdentity,
    snapshot: FileSnapshotId,
    permit: LoadPermit,
}

struct SystemImportClaim {
    key: DependencyName,
    descriptor: blueos_loader::PublishedImageDescriptor,
}

/// One first-load system image and its unique registry publication authority.
pub struct SystemCandidatePermit {
    pub key: DependencyName,
    pub identity: ArtifactIdentity,
    pub permit: LoadPermit,
}

/// Registry authority accumulated while replaying a namespace plan.
pub struct ResolverAuthorities {
    pub permits: Vec<SystemCandidatePermit>,
    pub leases: Vec<SystemDsoLease>,
    /// Identity-to-canonical-key mapping for every system image in the plan.
    /// Publication uses this instead of optional ELF SONAME metadata.
    pub system_images: Vec<(ArtifactIdentity, DependencyName)>,
}

/// Resolve a fully planned application namespace into linker artifacts.
pub struct NamespaceArtifactResolver {
    plan: NamespaceLoadPlan,
    batch_loads: Vec<(DependencyName, LoadPermit)>,
    batch_imports: Vec<(
        DependencyName,
        SystemDsoLease,
        blueos_loader::PublishedImageDescriptor,
    )>,
    candidates: Vec<SystemCandidateClaim>,
    leases: Vec<SystemDsoLease>,
    imports: Vec<SystemImportClaim>,
    opened_private: Vec<ArtifactIdentity>,
}

impl NamespaceArtifactResolver {
    /// Atomically acquire the plan's whole system closure. Waiting and retrying
    /// happens here, before the dynamic linker allocates an image.
    pub fn new(
        plan: NamespaceLoadPlan,
        registry: SystemDsoRegistry,
        domain: LinkDomainId,
    ) -> LoadResult<Self> {
        let PreparedSystemBatch { loads, imports } = loop {
            match registry.acquire_batch(domain, plan.system_keys()) {
                AcquireBatchOutcome::Acquired(batch) => break batch,
                AcquireBatchOutcome::Pending(wait) => wait.wait(),
            }
        };
        Ok(Self {
            plan,
            batch_loads: loads,
            batch_imports: imports,
            candidates: Vec::new(),
            leases: Vec::new(),
            imports: Vec::new(),
            opened_private: Vec::new(),
        })
    }

    /// Reopen the planned root and verify that it is still the same snapshot.
    pub fn root_artifact(&self) -> LoadResult<ResolvedArtifact<VfsElfReader>> {
        self.open_planned(
            &self.plan.images()[self.plan.root()],
            ImageOwnership::SessionPrivate,
        )
    }

    /// Hand all registry authority to the publisher after dependency closure.
    pub fn finish_resolution(&mut self) -> ResolverAuthorities {
        let permits = core::mem::take(&mut self.candidates)
            .into_iter()
            .map(|claim| SystemCandidatePermit {
                key: claim.key,
                identity: claim.identity,
                permit: claim.permit,
            })
            .collect();
        let mut leases = core::mem::take(&mut self.leases);
        leases.extend(
            core::mem::take(&mut self.batch_imports)
                .into_iter()
                .map(|(_, lease, _)| lease),
        );
        let system_images = self
            .plan
            .images()
            .iter()
            .filter_map(|image| {
                image
                    .system_key()
                    .map(|key| (image.identity().clone(), key.clone()))
            })
            .collect();
        ResolverAuthorities {
            permits,
            leases,
            system_images,
        }
    }

    fn open_planned(
        &self,
        image: &PlannedImage,
        ownership: ImageOwnership,
    ) -> LoadResult<ResolvedArtifact<VfsElfReader>> {
        let file = open_path(image.path(), libc::O_RDONLY, 0).map_err(|_| backend_error())?;
        let reader = VfsElfReader::new(file);
        let snapshot = reader.snapshot_id();
        if snapshot != image.snapshot() {
            return Err(source_changed());
        }
        let identity = image.identity().clone();
        Ok(ResolvedArtifact::new(identity, ownership, reader))
    }

    fn planned_provider_index(&self, request: &DependencyRequest<'_>) -> LoadResult<usize> {
        let requester = self
            .plan
            .images()
            .iter()
            .position(|image| image.identity() == request.requester().identity())
            .ok_or_else(backend_error)?;
        self.plan
            .edges()
            .iter()
            .find(|edge| edge.requester() == requester && edge.request() == request.needed())
            .map(|edge| edge.provider())
            .ok_or_else(|| unresolved(request.needed()))
    }

    fn resolve_system(
        &mut self,
        provider_index: usize,
    ) -> LoadResult<DependencyResolution<VfsElfReader>> {
        let provider = &self.plan.images()[provider_index];
        let key = provider.system_key().ok_or_else(backend_error)?.clone();

        if let Some(claim) = self.candidates.iter().find(|claim| claim.key == key) {
            if claim.identity != *provider.identity() || claim.snapshot != provider.snapshot() {
                return Err(source_changed());
            }
            return self
                .open_planned(provider, ImageOwnership::SystemCandidate)
                .map(DependencyResolution::Load);
        }

        if let Some((_, permit)) = take_by_key(&mut self.batch_loads, &key, |item| &item.0) {
            let artifact = self.open_planned(provider, ImageOwnership::SystemCandidate)?;
            self.candidates.push(SystemCandidateClaim {
                key: key.clone(),
                identity: provider.identity().clone(),
                snapshot: provider.snapshot(),
                permit,
            });
            log::info!("DSO_LOAD path={}", provider.path());
            return Ok(DependencyResolution::Load(artifact));
        }

        if let Some((_, lease, descriptor)) =
            take_by_key(&mut self.batch_imports, &key, |item| &item.0)
        {
            if descriptor.identity() != provider.identity() {
                return Err(source_changed());
            }
            self.leases.push(lease);
            self.imports.push(SystemImportClaim {
                key: key.clone(),
                descriptor: descriptor.clone(),
            });
            log::info!("DSO_REUSE path={}", provider.path());
            return Ok(DependencyResolution::Import(ImportedImageDescriptor::new(
                descriptor,
            )));
        }

        if let Some(claim) = self.imports.iter().find(|claim| claim.key == key) {
            return Ok(DependencyResolution::Import(ImportedImageDescriptor::new(
                claim.descriptor.clone(),
            )));
        }
        Err(backend_error())
    }
}

impl ArtifactResolver for NamespaceArtifactResolver {
    type Reader = VfsElfReader;

    fn resolve(
        &mut self,
        request: &DependencyRequest<'_>,
    ) -> LoadResult<DependencyResolution<Self::Reader>> {
        let provider_index = self.planned_provider_index(request)?;
        if self.plan.images()[provider_index].system() {
            self.resolve_system(provider_index)
        } else {
            let provider = &self.plan.images()[provider_index];
            if !self.opened_private.contains(provider.identity()) {
                log::info!("NS_LOAD path={}", provider.path());
                self.opened_private.push(provider.identity().clone());
            }
            self.open_planned(provider, ImageOwnership::SessionPrivate)
                .map(DependencyResolution::Load)
        }
    }
}

fn take_by_key<T>(
    items: &mut Vec<T>,
    key: &DependencyName,
    key_of: impl Fn(&T) -> &DependencyName,
) -> Option<T> {
    let position = items.iter().position(|item| key_of(item) == key)?;
    Some(items.swap_remove(position))
}

/// Encode a frozen snapshot into the loader's opaque file identity.
pub(crate) fn identity_from_snapshot(
    snapshot: FileSnapshotId,
    build_id: Option<&[u8]>,
) -> ArtifactIdentity {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&snapshot.fs_instance.to_le_bytes());
    bytes[8..16].copy_from_slice(&snapshot.inode.to_le_bytes());
    bytes[16..24].copy_from_slice(&snapshot.content_generation.to_le_bytes());
    bytes[24..32].copy_from_slice(&snapshot.len.to_le_bytes());
    ArtifactIdentity::new(
        FileIdentity::from_bytes(&bytes),
        snapshot.content_generation,
        build_id.map(BuildId::from_bytes),
    )
}

fn backend_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}

fn source_changed() -> LoadError {
    LoadError::new(LoadErrorKind::SourceChanged, ErrorContext::None)
}

fn unresolved(needed: &DependencyName) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Dependency {
            requester: 0,
            needed: needed.as_bytes().into(),
        },
    )
}
