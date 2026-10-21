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

//! Immutable artifacts and host dependency selection.
use crate::{reader::ElfReader, ArtifactId, ImageKey, LoadResult};

#[derive(Clone, Debug)]
pub struct ArtifactInfo {
    key: ImageKey,
    managed: bool,
}
impl ArtifactInfo {
    pub fn new(key: ImageKey, managed: bool) -> Self {
        Self { key, managed }
    }
    pub fn key(&self) -> &ImageKey {
        &self.key
    }
    pub const fn is_managed(&self) -> bool {
        self.managed
    }
}

/// Keeps the source snapshot alive throughout discovery and mapping.
#[must_use = "the immutable reader must survive discovery and mapping"]
pub struct OpenedArtifact<R: ElfReader> {
    pub(crate) reader: R,
    pub(crate) artifact: ArtifactId,
}
impl<R: ElfReader> OpenedArtifact<R> {
    pub fn new(reader: R, artifact: ArtifactId) -> Self {
        Self { reader, artifact }
    }
    pub fn reader(&self) -> &R {
        &self.reader
    }
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact
    }
}

/// Host artifact lookup. `open` returns an immutable version for the complete
/// attempt; an ArtifactId identifies those bytes, independently of the lookup key.
/// Use a filesystem snapshot, immutable storage or write exclusion across reads.
pub trait ArtifactResolver {
    type Source: Clone;
    type Reader: ElfReader;
    fn info<'a>(&self, source: &'a Self::Source) -> &'a ArtifactInfo;
    fn resolve(&mut self, requester: &Self::Source, needed: &[u8]) -> LoadResult<Self::Source>;
    fn open(&mut self, source: &Self::Source) -> LoadResult<OpenedArtifact<Self::Reader>>;
}
