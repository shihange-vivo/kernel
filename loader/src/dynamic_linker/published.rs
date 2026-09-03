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

//! The published/imported system image contract (C23-a).
//!
//! A [`PublishedImageDescriptor`] is the immutable, loader-neutral snapshot of
//! a Ready system DSO that a registry keeps long-term. It carries exactly what
//! a later application needs to *import* that image — identity, SONAME,
//! ownership, the mapped allocation descriptor (no lease authority), the load
//! bias, the published runtime regions, the export surface, the program-header
//! summary and the sealed state — so a second link binds against the same
//! provider without re-opening, re-mapping, re-relocating or re-sealing it.
//!
//! The descriptor never holds an [`AllocationLease`](crate::memory::AllocationLease):
//! the unique lease stays in the publisher's receipt, and the registry's own
//! `SystemDsoLease` lives outside this crate (§12.1).

use alloc::{boxed::Box, vec::Vec};

use crate::{
    address::{TargetAddress, TargetRange},
    dynamic_linker::{
        artifact::{ArtifactIdentity, DependencyName, ImageOwnership},
        symbol::SymbolTable,
        ProgramHeaderRuntimeInfo,
    },
    image::SealedState,
    memory::ImageAllocation,
    MemoryPermissions,
};

/// One published runtime region of a Ready image, sufficient for control-flow
/// and data target range checks during a later import (§12.1).
#[derive(Clone, Copy, Debug)]
pub struct PublishedRegion {
    runtime_range: TargetRange,
    permissions: MemoryPermissions,
}

impl PublishedRegion {
    #[inline]
    pub(crate) const fn new(runtime_range: TargetRange, permissions: MemoryPermissions) -> Self {
        Self {
            runtime_range,
            permissions,
        }
    }

    #[inline]
    pub const fn runtime_range(&self) -> TargetRange {
        self.runtime_range
    }

    #[inline]
    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}

/// The frozen export surface of a Ready image, retained so a later import can
/// resolve symbols against it without re-decoding the image (§12.1).
///
/// The inner table is kept crate-private: only the loader performs lookups.
pub struct PublishedSymbolTable {
    table: SymbolTable,
}

impl PublishedSymbolTable {
    #[inline]
    pub(crate) const fn new(table: SymbolTable) -> Self {
        Self { table }
    }

    #[inline]
    pub(crate) const fn table(&self) -> &SymbolTable {
        &self.table
    }

    /// Owned metadata bytes retained by the export surface, charged against
    /// `SessionLimits::total_runtime_metadata_bytes` when imported (§12.1).
    #[inline]
    pub fn metadata_bytes(&self) -> u64 {
        self.table.metadata_bytes()
    }
}

/// The immutable, loader-neutral snapshot of a Ready system DSO (§12.1).
pub struct PublishedImageDescriptor {
    identity: ArtifactIdentity,
    soname: Option<DependencyName>,
    ownership: ImageOwnership,
    allocation: ImageAllocation,
    load_bias: TargetAddress,
    regions: Vec<PublishedRegion>,
    exports: PublishedSymbolTable,
    program_headers: ProgramHeaderRuntimeInfo,
    sealed: SealedState,
}

impl PublishedImageDescriptor {
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        identity: ArtifactIdentity,
        soname: Option<DependencyName>,
        ownership: ImageOwnership,
        allocation: ImageAllocation,
        load_bias: TargetAddress,
        regions: Vec<PublishedRegion>,
        exports: PublishedSymbolTable,
        program_headers: ProgramHeaderRuntimeInfo,
        sealed: SealedState,
    ) -> Self {
        Self {
            identity,
            soname,
            ownership,
            allocation,
            load_bias,
            regions,
            exports,
            program_headers,
            sealed,
        }
    }

    #[inline]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    #[inline]
    pub const fn soname(&self) -> Option<&DependencyName> {
        self.soname.as_ref()
    }

    #[inline]
    pub const fn ownership(&self) -> ImageOwnership {
        self.ownership
    }

    /// The mapped allocation descriptor. This carries no lease authority: the
    /// unique lease remains in the publisher's receipt (§12.1).
    #[inline]
    pub const fn allocation(&self) -> ImageAllocation {
        self.allocation
    }

    #[inline]
    pub const fn load_bias(&self) -> TargetAddress {
        self.load_bias
    }

    #[inline]
    pub fn regions(&self) -> &[PublishedRegion] {
        &self.regions
    }

    #[inline]
    pub const fn program_headers(&self) -> &ProgramHeaderRuntimeInfo {
        &self.program_headers
    }

    #[inline]
    pub(crate) const fn exports(&self) -> &SymbolTable {
        self.exports.table()
    }

    #[inline]
    pub(crate) const fn sealed(&self) -> &SealedState {
        &self.sealed
    }
}

/// A Ready provider handed back by the resolver instead of a reader (§12.1).
///
/// Importing an image joins it to the dependency graph and symbol scopes while
/// skipping allocation, relocation, seal and init planning. The descriptor is
/// owned by value: the resolver produces it from the registry, and the session
/// consumes it exactly once.
pub struct ImportedImageDescriptor {
    descriptor: Box<PublishedImageDescriptor>,
}

impl ImportedImageDescriptor {
    #[inline]
    pub(crate) fn new(descriptor: PublishedImageDescriptor) -> Self {
        Self {
            descriptor: Box::new(descriptor),
        }
    }

    #[inline]
    pub const fn descriptor(&self) -> &PublishedImageDescriptor {
        &self.descriptor
    }

    #[inline]
    pub(crate) fn into_descriptor(self) -> PublishedImageDescriptor {
        *self.descriptor
    }
}
