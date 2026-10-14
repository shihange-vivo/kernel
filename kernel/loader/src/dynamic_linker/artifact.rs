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

//! Backend identities, session-local image ids and backing ownership.

use alloc::vec::Vec;

use crate::{error::LoadErrorKind, LoadError, LoadResult};

/// Opaque backend identity of one loaded artifact. Equal bytes must refer
/// to the same backing and generation; the loader does not interpret them.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactIdentity {
    bytes: Vec<u8>,
}

impl ArtifactIdentity {
    pub fn from_bytes(bytes: &[u8]) -> LoadResult<Self> {
        Ok(Self {
            bytes: try_copy_bytes(bytes)?,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn try_clone(&self) -> LoadResult<Self> {
        Self::from_bytes(&self.bytes)
    }

    pub(crate) fn metadata_bytes(&self) -> u64 {
        self.bytes.len() as u64
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
    /// sealed, contributed to the graph/scopes without a fresh load.
    ExternalReady,
    /// An already initialized image owned by the importing application.
    /// It participates in private scopes but carries no new allocation or
    /// lifecycle entries. The host must retain its original publication.
    NamespaceReady,
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
