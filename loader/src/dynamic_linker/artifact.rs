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

//! Artifact identity and resolver contract for the Phase 0.5 `DynamicLinker`.
//!
//! The resolver is deliberately free of any VFS, environment variable, current
//! directory, or `librs` dependency: it answers a [`DependencyRequest`] from a
//! trusted catalog of already-opened snapshots. Phase 1's application resolver
//! adapts that same contract to signed application packages.

use alloc::vec::Vec;

use crate::{
    error::{LoadError, LoadErrorKind, LoadResult},
    reader::ElfReader,
};

/// Opaque, comparable snapshot identity supplied by the artifact backend.
///
/// Two [`FileIdentity`] values compare equal only when they refer to the same
/// backend snapshot; equality never derives from a path or a SONAME string.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileIdentity {
    bytes: Vec<u8>,
}

impl FileIdentity {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    fn try_clone(&self) -> LoadResult<Self> {
        Ok(Self {
            bytes: try_copy_bytes(&self.bytes)?,
        })
    }

    fn metadata_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// Opaque build identifier (e.g. a GNU build-id note) attached to an artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BuildId {
    bytes: Vec<u8>,
}

impl BuildId {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    fn try_clone(&self) -> LoadResult<Self> {
        Ok(Self {
            bytes: try_copy_bytes(&self.bytes)?,
        })
    }

    fn metadata_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// How one artifact participates in a link session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRole {
    /// The link root: must carry a canonical entry fully inside an executable
    /// region and is published as the application entry.
    ExecutableRoot,
    /// A dependent shared object: may have `e_entry == 0` and must provide a
    /// bounded, NUL-terminated `DT_SONAME`.
    SharedObject,
}

/// Stable identity of one loaded artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactIdentity {
    file: FileIdentity,
    generation: u64,
    build_id: Option<BuildId>,
}

impl ArtifactIdentity {
    #[inline]
    pub const fn new(file: FileIdentity, generation: u64, build_id: Option<BuildId>) -> Self {
        Self {
            file,
            generation,
            build_id,
        }
    }

    #[inline]
    pub const fn file(&self) -> &FileIdentity {
        &self.file
    }

    #[inline]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[inline]
    pub const fn build_id(&self) -> Option<&BuildId> {
        self.build_id.as_ref()
    }

    pub(crate) fn try_clone(&self) -> LoadResult<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            generation: self.generation,
            build_id: self.build_id.as_ref().map(BuildId::try_clone).transpose()?,
        })
    }

    pub(crate) fn metadata_bytes(&self) -> u64 {
        self.file
            .metadata_bytes()
            .saturating_add(self.build_id.as_ref().map_or(0, BuildId::metadata_bytes))
    }
}

/// Owned, validated dependency name (a `DT_NEEDED` or `DT_SONAME` value).
///
/// Construction validates that the source bytes form a single NUL-terminated
/// name with no embedded NUL; the stored value is the name without its
/// terminator. First-version comparison is by ELF raw bytes; the resolver's
/// catalog key must canonicalize consistently rather than normalizing case or
/// path separators per layer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DependencyName {
    name: Vec<u8>,
}

impl DependencyName {
    /// Validate and copy `bytes`, which must end with exactly one NUL and
    /// contain no other NUL or empty name before it.
    pub fn from_terminated(bytes: &[u8]) -> LoadResult<Self> {
        let name_len = bytes.len().checked_sub(1).filter(|_| {
            bytes.last() == Some(&0) && bytes[..bytes.len() - 1].iter().all(|byte| *byte != 0)
        });
        let Some(name_len) = name_len else {
            return Err(LoadError::new(
                LoadErrorKind::BadElf,
                crate::error::ErrorContext::None,
            ));
        };
        if name_len == 0 {
            return Err(LoadError::new(
                LoadErrorKind::BadElf,
                crate::error::ErrorContext::None,
            ));
        }
        Ok(Self {
            name: try_copy_bytes(&bytes[..name_len])?,
        })
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.name
    }

    pub(crate) fn try_clone(&self) -> LoadResult<Self> {
        Ok(Self {
            name: try_copy_bytes(&self.name)?,
        })
    }
}

/// A request for one `DT_NEEDED` dependency, rooted at its requester.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyRequest<'a> {
    requester: &'a ArtifactIdentity,
    needed: &'a DependencyName,
    domain: LinkDomainId,
}

impl<'a> DependencyRequest<'a> {
    #[inline]
    pub const fn new(
        requester: &'a ArtifactIdentity,
        needed: &'a DependencyName,
        domain: LinkDomainId,
    ) -> Self {
        Self {
            requester,
            needed,
            domain,
        }
    }

    #[inline]
    pub const fn requester(&self) -> &ArtifactIdentity {
        self.requester
    }

    #[inline]
    pub const fn needed(&self) -> &DependencyName {
        self.needed
    }

    #[inline]
    pub const fn domain(&self) -> LinkDomainId {
        self.domain
    }
}

/// Whether a resolved artifact is owned by this link session or shared with the
/// system DSO catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageOwnership {
    /// Owned by this link session: allocated, relocated and sealed here.
    SessionPrivate,
    /// A candidate to become a shared system DSO, loaded for the first time.
    SystemCandidate,
    /// A Ready system DSO imported from the registry: already relocated and
    /// sealed, contributed to the graph/scopes without a fresh load (§12.1).
    ExternalReady,
}

/// A resolved artifact: its identity and a reader over the same snapshot.
pub struct ResolvedArtifact<R> {
    identity: ArtifactIdentity,
    ownership: ImageOwnership,
    reader: R,
}

impl<R> ResolvedArtifact<R> {
    #[inline]
    pub const fn new(identity: ArtifactIdentity, ownership: ImageOwnership, reader: R) -> Self {
        Self {
            identity,
            ownership,
            reader,
        }
    }

    #[inline]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    #[inline]
    pub const fn ownership(&self) -> ImageOwnership {
        self.ownership
    }

    #[inline]
    pub const fn reader(&self) -> &R {
        &self.reader
    }

    #[inline]
    pub fn into_reader(self) -> R {
        self.reader
    }

    #[inline]
    pub fn into_parts(self) -> (ArtifactIdentity, ImageOwnership, R) {
        (self.identity, self.ownership, self.reader)
    }
}

/// Resolves a dependency name to a concrete artifact snapshot.
///
/// `resolve` returns a reader over the exact snapshot identified by the
/// returned [`ArtifactIdentity`]. A failed resolution must leave no loading
/// entry behind.
pub trait ArtifactResolver {
    type Reader: ElfReader;

    fn resolve(
        &mut self,
        request: &DependencyRequest<'_>,
    ) -> LoadResult<ResolvedArtifact<Self::Reader>>;
}

/// What a [`DependencyRequest`] resolved into (§12.1).
///
/// `Load` hands the session a reader over a snapshot it must load through
/// S0–S8; `Import` hands it a Ready provider already relocated and sealed by a
/// previous link, to be joined to the graph and scopes without a fresh load.
pub enum DependencyResolution<R> {
    Load(ResolvedArtifact<R>),
    Import(super::ImportedImageDescriptor),
}

fn try_copy_bytes(bytes: &[u8]) -> LoadResult<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|_| {
        LoadError::new(LoadErrorKind::OutOfMemory, crate::error::ErrorContext::None)
    })?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

/// Stable identifier of a loaded image within one session.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ImageId(u32);

impl ImageId {
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Identifier of the link domain an artifact is resolved into.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LinkDomainId(u32);

impl LinkDomainId {
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}
