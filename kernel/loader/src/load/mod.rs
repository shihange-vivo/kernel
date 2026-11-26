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

//! Complete loading entry points and their finalized image owners.

#[cfg(enable_dynamic_linker)]
mod linked;
mod single;

#[cfg(enable_dynamic_linker)]
pub(crate) use linked::SealedBatch;
#[cfg(enable_dynamic_linker)]
pub use linked::{load_and_link, LoadedImages, LoadedObject, PluginLoad};
pub use single::{load_elf, map_elf_for_interpreter, LoadedImage};

#[cfg(enable_dynamic_linker)]
use crate::profile::{DependencyLimits, LinkLimits};
use crate::profile::{LoadLimits, LoadProfile, LoadPurpose};

/// Per-image loading policy for a standalone ELF or a dependency graph root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadRequest {
    profile: LoadProfile,
    limits: LoadLimits,
    purpose: LoadPurpose,
}

impl LoadRequest {
    /// Require an application entry unless changed to `SharedObject`.
    pub const fn new(profile: LoadProfile, limits: LoadLimits) -> Self {
        Self {
            profile,
            limits,
            purpose: LoadPurpose::Executable,
        }
    }

    pub const fn with_purpose(mut self, purpose: LoadPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub const fn purpose(&self) -> LoadPurpose {
        self.purpose
    }

    pub const fn profile(&self) -> &LoadProfile {
        &self.profile
    }

    pub const fn limits(&self) -> &LoadLimits {
        &self.limits
    }
}

/// Per-image policy and whole-graph limits for `load_and_link`.
#[cfg(enable_dynamic_linker)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadAndLinkRequest {
    load_request: LoadRequest,
    dependency_limits: DependencyLimits,
    link_limits: LinkLimits,
}

#[cfg(enable_dynamic_linker)]
impl LoadAndLinkRequest {
    /// Use the default dependency and link limits with this image policy.
    pub const fn new(load_request: LoadRequest) -> Self {
        Self {
            load_request,
            dependency_limits: DependencyLimits::DEFAULT,
            link_limits: LinkLimits::DEFAULT,
        }
    }

    pub const fn with_dependency_limits(mut self, limits: DependencyLimits) -> Self {
        self.dependency_limits = limits;
        self
    }

    pub const fn with_link_limits(mut self, limits: LinkLimits) -> Self {
        self.link_limits = limits;
        self
    }

    const fn profile(&self) -> &LoadProfile {
        self.load_request.profile()
    }

    pub(crate) const fn into_parts(self) -> (LoadRequest, DependencyLimits, LinkLimits) {
        (self.load_request, self.dependency_limits, self.link_limits)
    }
}
