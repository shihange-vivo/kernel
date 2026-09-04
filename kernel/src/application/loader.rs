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

//! `ApplicationLoader`: the staged link driver and registry hand-off (C26, §15).
//!
//! [`ApplicationLoader`] is the bridge between the loader's neutral staged API
//! and the kernel's VFS/memory/cache/registry services. It drives
//! `DynamicLinker` through the `begin → close_dependencies → finish_resolution
//! → freeze_scopes → relocate → seal → publish` sequence (§12.1), hands the
//! resolver's accumulated registry authority to the kernel link publisher, and
//! — once `publish` returns the committed [`LinkProduct`] — advances every
//! first-loading system candidate through the registry to `Ready` by SONAME
//! match (§13.3).
//!
//! The loader is a cloneable handle: it keeps the fixed catalog, the shared
//! registry and the shared-flat memory service, and mints a fresh linker,
//! resolver, cache and publisher per link. It performs no thread creation and
//! does not install the product into the group — the [`crate::application::manager`]
//! `prepare` closure builds the start storage and calls
//! [`ThreadGroup::install_link_product`](crate::application::group::ThreadGroup::install_link_product)
//! after this returns, so the infallible install is the manager's last step
//! (§15.2).

use alloc::vec::Vec;

use blueos_loader::{
    ArchitectureCodeCache, ArmRelocator, CacheRequirements, DynamicLinker, ImageOwnership,
    LinkDomainId, LinkProduct, LoadError, LoadErrorKind, LoadProfile, LoadResult,
    ResolvedArtifact, SessionLimits,
};

use crate::{
    application::{
        adapters::{
            resolver::{
                identity_from_snapshot, ApplicationArtifactResolver, ResolverAuthorities,
                SystemCandidatePermit,
            },
            system_paths::SystemLibraryPaths,
            vfs_reader::VfsElfReader,
        },
        group::ThreadGroup,
        publication::{KernelLinkPublisher, KernelLinkReceipt},
        registry::SystemDsoRegistry,
    },
    vfs::open_path,
};

/// A cloneable handle that links a dynamic application against the shared-flat
/// memory service and publishes its first-loading system DSOs (§15).
pub struct ApplicationLoader {
    catalog: &'static SystemLibraryPaths,
    registry: SystemDsoRegistry,
    memory: crate::application::adapters::flat_memory::FlatImageMemory,
    domain: LinkDomainId,
}

impl ApplicationLoader {
    /// Build a loader over a fixed catalog, shared registry, shared-flat memory
    /// service and a fixed link domain.
    pub fn new(
        catalog: &'static SystemLibraryPaths,
        registry: SystemDsoRegistry,
        memory: crate::application::adapters::flat_memory::FlatImageMemory,
        domain: LinkDomainId,
    ) -> Self {
        Self {
            catalog,
            registry,
            memory,
            domain,
        }
    }

    /// Open `path`, freeze its snapshot and derive the session-private root
    /// artifact identity from that same snapshot (§12.2). The root is always
    /// [`ImageOwnership::SessionPrivate`]; system candidates are produced only
    /// by the resolver during dependency closure.
    pub fn open_root(
        &self,
        path: &'static str,
        build_id: Option<&'static [u8]>,
    ) -> LoadResult<ResolvedArtifact<VfsElfReader>> {
        let file = open_path(path, libc::O_RDONLY, 0).map_err(|_| loader_error())?;
        let reader = VfsElfReader::new(file);
        let snapshot = reader.snapshot_id();
        let identity = identity_from_snapshot(snapshot, build_id);
        Ok(ResolvedArtifact::new(
            identity,
            ImageOwnership::SessionPrivate,
            reader,
        ))
    }

    /// Run a complete staged link of `root` under `profile` into `group`, then
    /// advance every first-loading system candidate to `Ready` (§12.1, §15.1).
    ///
    /// The returned [`LinkProduct`] is fully committed and carries the receipt
    /// that owns every raw allocation lease; the caller installs it into the
    /// group and builds the start storage (§15.2, §15.3). On any failure the
    /// session rolls back every absorbed allocation and the still-armed registry
    /// permits/leases drop, cancelling the load (§13.5).
    pub fn link(
        &self,
        root: ResolvedArtifact<VfsElfReader>,
        profile: LoadProfile,
        group: &ThreadGroup,
    ) -> LoadResult<LinkProduct<KernelLinkReceipt>> {
        let linker = DynamicLinker::new(ArmRelocator);
        let mut memory = self.memory.clone();
        let mut resolver = ApplicationArtifactResolver::new(self.catalog, self.registry.clone());
        let mut cache = ArchitectureCodeCache::new(CacheRequirements::CURRENT_EXECUTION_CONTEXT);
        let mut publisher = KernelLinkPublisher::new(group.clone());

        let mut building = linker.begin(
            root,
            profile,
            self.domain,
            SessionLimits::DEFAULT,
            &mut memory,
        )?;
        building.close_dependencies(&mut resolver)?;
        let ResolverAuthorities { permits, leases } = resolver.finish_resolution();
        publisher.import_leases(leases);

        let product = building
            .freeze_scopes()?
            .relocate()?
            .seal(&mut cache)?
            .publish(&mut publisher)?;

        self.hand_off(permits, &product)?;

        Ok(product)
    }

    /// Advance each first-loading system candidate through the registry to
    /// `Ready`, matching its permit to the committed image by SONAME (§13.3).
    fn hand_off(
        &self,
        permits: Vec<SystemCandidatePermit>,
        product: &LinkProduct<KernelLinkReceipt>,
    ) -> LoadResult<()> {
        for candidate in permits {
            let image = product
                .context()
                .images()
                .iter()
                .find(|image| {
                    image.descriptor().ownership() == ImageOwnership::SystemCandidate
                        && image.descriptor().soname() == Some(&candidate.soname)
                })
                .ok_or_else(loader_error)?;
            let relocated = self
                .registry
                .publish_relocated(candidate.permit)
                .map_err(|_| loader_error())?;
            let fini = product.fini_plan().for_image(image.owner())?;
            self.registry
                .mark_ready(relocated, image.descriptor().clone(), fini)
                .map_err(|_| loader_error())?;
        }
        Ok(())
    }
}

fn loader_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, blueos_loader::ErrorContext::None)
}
