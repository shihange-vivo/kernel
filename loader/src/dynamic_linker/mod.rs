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

//! Phase 0.5 multi-image dynamic linking (C11–C17).
//!
//! C11-b delivered the artifact/resolver contract; C12 adds the bounded
//! dependency graph. Scope (C14) and session typestate (C15) land later.

mod artifact;
mod graph;

pub use artifact::{
    ArtifactIdentity, ArtifactResolver, ArtifactRole, BuildId, DependencyName, DependencyRequest,
    FileIdentity, ImageId, ImageOwnership, LinkDomainId, ResolvedArtifact,
};
