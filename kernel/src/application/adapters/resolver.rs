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

//! `ArtifactResolver` adapter over the system catalog and the DSO registry
//! (C24, §12.2).
//!
//! [`ApplicationArtifactResolver`] turns a `DT_NEEDED` byte name into either a
//! fresh [`DependencyResolution::Load`] (a `SystemCandidate` the session must
//! load and later publish) or a [`DependencyResolution::Import`] (a Ready
//! instance already relocated and sealed by an earlier link). It never searches
//! the current directory, `LD_LIBRARY_PATH`, `RPATH`/`RUNPATH` or an
//! application-package `lib/` directory: a system dependency resolves only
//! through an exact byte-name hit in the fixed [`SystemLibraryPaths`] catalog.
//!
//! The resolver owns the registry authority it acquires: each minted
//! [`LoadPermit`] and [`SystemDsoLease`] is retained for the duration of the
//! staged link and handed over by [`ApplicationArtifactResolver::finish_resolution`]
//! so the kernel link publisher can advance it (C26). If the resolver is
//! dropped before that hand-off — the link failed — the retained permits and
//! leases drop too, cancelling the load or releasing the import (§13.5).

use alloc::vec::Vec;

use blueos_loader::{
    ArtifactIdentity, ArtifactResolver, BuildId, DependencyName, DependencyRequest,
    DependencyResolution, ErrorContext, FileIdentity, ImageOwnership, ImportedImageDescriptor,
    LoadError, LoadErrorKind, LoadResult, ResolvedArtifact,
};

use crate::{
    application::{
        adapters::{system_paths::SystemLibraryPaths, vfs_reader::VfsElfReader},
        registry::{AcquireOutcome, LoadPermit, SystemDsoLease, SystemDsoRegistry},
    },
    vfs::{open_path, FileSnapshotId},
};

/// A `SystemCandidate` claimed for this link but not yet published.
///
/// The `permit` is the sole publication authority for its generation and stays
/// here until `finish_resolution`; the remaining fields de-duplicate a second
/// `DT_NEEDED` of the same SONAME *within one link* so the resolver does not
/// re-request (and block on) a generation it already owns.
struct SystemCandidateClaim {
    permit: LoadPermit,
    soname: DependencyName,
    snapshot: FileSnapshotId,
}

/// The registry authorities a staged link accumulated (C26 hands them to the
/// kernel link publisher's receipt).
pub struct ResolverAuthorities {
    /// Publication permits for every `SystemCandidate` this link must load.
    pub permits: Vec<LoadPermit>,
    /// Counted references to every Ready instance this link imported.
    pub leases: Vec<SystemDsoLease>,
}

/// Resolves system dependencies against the fixed catalog and the registry.
pub struct ApplicationArtifactResolver {
    catalog: &'static SystemLibraryPaths,
    registry: SystemDsoRegistry,
    candidates: Vec<SystemCandidateClaim>,
    leases: Vec<SystemDsoLease>,
}

impl ApplicationArtifactResolver {
    /// Build a resolver over a fixed catalog and a shared registry.
    pub fn new(catalog: &'static SystemLibraryPaths, registry: SystemDsoRegistry) -> Self {
        Self {
            catalog,
            registry,
            candidates: Vec::new(),
            leases: Vec::new(),
        }
    }

    /// Hand over the permits and leases acquired across `resolve` calls, leaving
    /// the resolver empty. The caller (the kernel link publisher) owns them from
    /// here on and must advance or drop them (§12.1, §13.3).
    pub fn finish_resolution(&mut self) -> ResolverAuthorities {
        let permits = core::mem::take(&mut self.candidates)
            .into_iter()
            .map(|claim| claim.permit)
            .collect();
        let leases = core::mem::take(&mut self.leases);
        ResolverAuthorities { permits, leases }
    }

    /// Open `entry`'s path, freeze its snapshot and derive the artifact identity
    /// from that same snapshot (§12.2: identity, reader and build-id come from
    /// one snapshot). The reader's generation re-check still guards against a
    /// mid-load write.
    fn open_candidate(
        &self,
        entry: &'static crate::application::adapters::system_paths::SystemLibraryEntry,
    ) -> LoadResult<(VfsElfReader, FileSnapshotId)> {
        let file = open_path(entry.path, libc::O_RDONLY, 0).map_err(|_| backend_error())?;
        let reader = VfsElfReader::new(file);
        let snapshot = reader.snapshot_id();
        Ok((reader, snapshot))
    }
}

impl ArtifactResolver for ApplicationArtifactResolver {
    type Reader = VfsElfReader;

    fn resolve(
        &mut self,
        request: &DependencyRequest<'_>,
    ) -> LoadResult<DependencyResolution<Self::Reader>> {
        let needed = request.needed();
        let domain = request.domain();
        let entry = self
            .catalog
            .resolve(needed.as_bytes())
            .ok_or_else(|| unresolved(needed))?;

        // Same-SONAME de-duplication within this link: a second `DT_NEEDED` of
        // an already-claimed SystemCandidate must not re-request (and block on)
        // the generation we still hold. Re-open the same trusted path, re-derive
        // the identity from the fresh snapshot, and let the loader's own
        // identity de-duplication record only the extra edge.
        if let Some(claim) = self.candidates.iter().find(|c| c.soname == *needed) {
            let (reader, snapshot) = self.open_candidate(entry)?;
            if snapshot != claim.snapshot {
                return Err(source_changed());
            }
            return Ok(DependencyResolution::Load(ResolvedArtifact::new(
                identity_from_snapshot(snapshot, entry.build_id),
                ImageOwnership::SystemCandidate,
                reader,
            )));
        }

        loop {
            match self.registry.acquire_or_begin_load(domain, needed.clone()) {
                AcquireOutcome::Permit(permit) => {
                    let (reader, snapshot) = self.open_candidate(entry)?;
                    self.candidates.push(SystemCandidateClaim {
                        permit,
                        soname: needed.clone(),
                        snapshot,
                    });
                    return Ok(DependencyResolution::Load(ResolvedArtifact::new(
                        identity_from_snapshot(snapshot, entry.build_id),
                        ImageOwnership::SystemCandidate,
                        reader,
                    )));
                }
                AcquireOutcome::Lease(lease) => {
                    // We hold the lease, so the instance cannot have dropped to
                    // `Quiescing`; `descriptor` is guaranteed Some.
                    let descriptor = self
                        .registry
                        .descriptor(domain, needed)
                        .ok_or_else(backend_error)?;
                    self.leases.push(lease);
                    return Ok(DependencyResolution::Import(
                        ImportedImageDescriptor::new(descriptor),
                    ));
                }
                // A concurrent link is mid-construction for this generation:
                // block (outside any loader-memory or manager lock) until it
                // resolves, then re-acquire (§13.3).
                AcquireOutcome::Pending(handle) => handle.wait(),
            }
        }
    }
}

/// Encode a frozen snapshot into the loader's opaque [`FileIdentity`] so two
/// identities compare equal only for the same `(fs_instance, inode, content
/// generation, len)`. The snapshot's content generation doubles as the
/// [`ArtifactIdentity`] generation: a reload of the same path after a write
/// yields a fresh identity rather than aliasing the old one.
fn identity_from_snapshot(
    snapshot: FileSnapshotId,
    build_id: Option<&'static [u8]>,
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
