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

//! Multi-image dynamic linking for applications and runtime shared objects.
//!
//! The module consumes mapped image metadata and a fixed dependency graph.
//! It owns symbol scopes, cross-image relocation, lifecycle plans and publication.
//! `loading` discovers and maps the closure; `image` decodes each ELF.
//! Start with `prepare` for the link flow and `session` for its state transitions.

mod artifact;
mod graph;
mod lifecycle;
mod prepare;
mod publish;
mod published;
mod relocate;
mod scope;
mod session;

pub(crate) use artifact::{ArtifactIdentity, ImageId, ImageOwnership};
pub(crate) use graph::{order_components, DependencyGraph};
pub(crate) use lifecycle::{LifecycleEntry, LifecyclePlans};
pub(crate) use prepare::prepare_link;
pub(crate) use publish::{
    CommittedImage, CommittingLinkProduct, LinkContext, LinkProduct, LinkPublisher,
    PreparedLinkManifest,
};
pub use published::ImageDependency;
pub(crate) use published::{
    ImportedImageDescriptor, PublishedImageDescriptor, PublishedLoadSnapshot, PublishedRegion,
};
pub(crate) use scope::{RelocationBinding, ResolvedSymbol, ScopeSet, SymbolRegionKind};
pub(crate) use session::{
    ImportedImage, LinkSession, LoadedSession, LoadedState, SealedSession, SessionImage,
    SessionUsage,
};
