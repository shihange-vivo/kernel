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

//! Complete-load orchestration and the host-facing API.
//!
//! Read `load` first: it connects dependency planning, atomic host acquisition,
//! image mapping, linking and publication. `source` and `repository` define
//! independent host capabilities; `planning` resolves sources and pinned snapshots;
//! `materialize` maps its indexed plan without rediscovering dependencies;
//! `publication` transfers allocations; `loaded` assembles result metadata.
//! ELF loading and linking algorithms live in `image` and `dynamic_linker`.

mod load;
mod loaded;
pub(crate) mod materialize;
pub(crate) mod planning;
mod publication;
mod repository;
mod source;

pub use load::{load, prepare_load, LoadRequest, LoadServices};
pub use loaded::{ImageDependency, ImageHandle, LifecycleEntry, LoadedImage};
pub use publication::{
    LoadPublisher, LoadResourceParts, LoadResources, PreparedLoad, PublicationManifest,
    RetainResources,
};
pub use repository::{
    ImageCandidate, ImagePin, ImageRepository, LoadReservation, LocalPin, LocalRepository,
    LocalReservation, NamespaceSnapshot, ReservedImage,
};
pub use source::{ArtifactInfo, ArtifactResolver, OpenedArtifact};
