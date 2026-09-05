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
    AllocationLease, ArchitectureCodeCache, ArmRelocator, CacheRequirements, DependencyName,
    DynamicLinker, ImageOwnership, LinkDomainId, LinkProduct, LoadError, LoadErrorKind,
    LoadProfile, LoadResult, ResolvedArtifact, SessionLimits,
};

use crate::{
    application::{
        adapters::{
            resolver::{identity_from_snapshot, ApplicationArtifactResolver, ResolverAuthorities, SystemCandidatePermit},
            system_paths::SystemLibraryPaths,
            vfs_reader::VfsElfReader,
        },
        group::ThreadGroup,
        publication::{KernelLinkPublisher, KernelLinkReceipt},
        registry::{
            SystemCandidateBacking, SystemDsoRegistry, SystemInitBatch,
        },
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

    /// The shared-flat memory service the loader links into (§15).
    /// The system DSO registry, for the init-completion path to advance the
    /// pending initialization batch (C31-c, §8.3).
    pub fn registry(&self) -> &SystemDsoRegistry {
        &self.registry
    }

    pub fn memory(&self) -> &crate::application::adapters::flat_memory::FlatImageMemory {
        &self.memory
    }

    /// Open `path`, freeze its snapshot and derive the session-private root
    /// artifact identity from that same snapshot (§12.2). The root is always
    /// [`ImageOwnership::SessionPrivate`]; system candidates are produced only
    /// by the resolver during dependency closure.
    pub fn open_root(
        &self,
        path: &str,
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
        let resolver = ApplicationArtifactResolver::new(self.catalog, self.registry.clone());
        self.link_with(root, profile, group, resolver)
    }

    /// Link a manifest-closed application package (C30, §7.2): the composite
    /// resolver follows the package manifest's private edges and consumes the
    /// atomically acquired system batch.
    #[cfg(boot_dynamic_seed)]
    pub fn link_package(
        &self,
        root: ResolvedArtifact<VfsElfReader>,
        package: &'static crate::application::package::ApplicationPackageManifest,
        profile: LoadProfile,
        group: &ThreadGroup,
    ) -> LoadResult<LinkProduct<KernelLinkReceipt>> {
        let root_identity = root.identity().clone();
        let resolver = crate::application::adapters::package_resolver::PackageArtifactResolver::new(
            package,
            self.catalog,
            self.registry.clone(),
            &root_identity,
            self.domain,
        )?;
        self.link_with(root, profile, group, resolver)
    }

    /// The shared staged-link pipeline: begin, close the dependency closure
    /// through `resolver`, freeze scopes, relocate, seal and publish, then
    /// advance every first-loading system candidate to `Ready` (§12.1, §15.1).
    fn link_with<Resolver>(
        &self,
        root: ResolvedArtifact<VfsElfReader>,
        profile: LoadProfile,
        group: &ThreadGroup,
        mut resolver: Resolver,
    ) -> LoadResult<LinkProduct<KernelLinkReceipt>>
    where
        Resolver: blueos_loader::ArtifactResolver<Reader = VfsElfReader> + ResolverFinish,
    {
        let linker = DynamicLinker::new(ArmRelocator);
        let mut memory = self.memory.clone();
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
        let ResolverAuthorities { permits, leases } = resolver.finish();
        publisher.import_leases(leases);

        let mut product = building
            .freeze_scopes()?
            .relocate()?
            .seal(&mut cache)?
            .publish(&mut publisher)?;

        // C31-c (§8.3): publish the whole system batch as Initializing and
        // hand the token to the group; ApplicationInitComplete advances it
        // to Ready (or the group's early exit fails it).
        let batch = self.hand_off(permits, &mut product)?;
        group
            .install_pending_system_batch(batch)
            .map_err(|_| loader_error())?;
        log_bindings(&product);
        log_lifecycle(&product);

        Ok(product)
    }

    /// Advance every first-loading system candidate to `Initializing` in one
    /// batch and move the receipt's system backings into the registry
    /// (C31-c, §8.3/§8.4). Returns the batch token the group holds until the
    /// application reports init completion.
    fn hand_off(
        &self,
        permits: Vec<SystemCandidatePermit>,
        product: &mut LinkProduct<KernelLinkReceipt>,
    ) -> LoadResult<SystemInitBatch> {
        // The receipt's raw system allocations are ordered by image id
        // (commit_batch partitions the link map in id order); pair each with
        // its candidate's SONAME for the permit match below.
        let allocations = product.publication_mut().take_system_allocations();
        let mut allocations_by_soname: Vec<(DependencyName, AllocationLease)> = product
            .context()
            .images()
            .iter()
            .filter(|image| image.descriptor().ownership() == ImageOwnership::SystemCandidate)
            .map(|image| {
                image
                    .descriptor()
                    .soname()
                    .cloned()
                    .ok_or_else(loader_error)
            })
            .collect::<LoadResult<Vec<_>>>()?
            .into_iter()
            .zip(allocations)
            .collect();
        if permits.len() != allocations_by_soname.len() {
            return Err(loader_error());
        }

        let mut relocated = Vec::new();
        relocated
            .try_reserve(permits.len())
            .map_err(|_| loader_error())?;
        let mut backings = Vec::new();
        backings
            .try_reserve(permits.len())
            .map_err(|_| loader_error())?;
        for candidate in permits {
            let allocation_index = allocations_by_soname
                .iter()
                .position(|(soname, _)| soname == &candidate.soname)
                .ok_or_else(loader_error)?;
            let (_, allocation) = allocations_by_soname.swap_remove(allocation_index);
            let image = product
                .context()
                .images()
                .iter()
                .find(|image| {
                    image.descriptor().ownership() == ImageOwnership::SystemCandidate
                        && image.descriptor().soname() == Some(&candidate.soname)
                })
                .ok_or_else(loader_error)?;
            relocated.push(self.registry.publish_relocated(candidate.permit)?);
            // A system candidate with no destructors has no plan entry; the
            // registry stores an empty plan for it.
            let fini_plan = product
                .lifecycle_plans()
                .system_fini()
                .iter()
                .find(|plan| plan.owner() == image.owner())
                .map(|plan| plan.plan().clone())
                .unwrap_or_default();
            backings.push(SystemCandidateBacking {
                descriptor: image.descriptor().clone(),
                fini_plan,
                allocation,
                // System-to-system dependency leases land with the C31-d SCC
                // edges; the first group holds the link's import leases.
                dependencies: alloc::vec![],
            });
        }
        self.registry
            .publish_relocated_batch(relocated, backings)
    }
}

/// The registry-authority hand-off both resolver flavors share (C30).
trait ResolverFinish {
    fn finish(&mut self) -> ResolverAuthorities;
}

impl ResolverFinish for ApplicationArtifactResolver {
    fn finish(&mut self) -> ResolverAuthorities {
        self.finish_resolution()
    }
}

#[cfg(boot_dynamic_seed)]
impl ResolverFinish
    for crate::application::adapters::package_resolver::PackageArtifactResolver
{
    fn finish(&mut self) -> ResolverAuthorities {
        self.finish_resolution()
    }
}

fn loader_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, blueos_loader::ErrorContext::None)
}

/// C31-b lifecycle oracle (§17.1, §8.2): surface the ownership-partitioned
/// plans and the frozen SCC snapshot so QEMU checkers can assert the init and
/// group/system fini sequences.
fn log_lifecycle(product: &LinkProduct<KernelLinkReceipt>) {
    let plans = product.lifecycle_plans();
    for (index, entry) in plans.startup().iter().enumerate() {
        log::info!(
            "LIFECYCLE_INIT index={} owner={} address={:#x}",
            index,
            entry.owner().get(),
            entry.function().get()
        );
    }
    for (index, entry) in plans.group_fini().iter().enumerate() {
        log::info!(
            "LIFECYCLE_GROUP_FINI index={} owner={}",
            index,
            entry.owner().get()
        );
    }
    for plan in plans.system_fini() {
        for entry in plan.plan().iter() {
            log::info!("LIFECYCLE_SYSTEM_FINI owner={}", entry.owner().get());
        }
    }
    for entry in product.link_map() {
        log::info!(
            "LINK_MAP owner={} soname={} bias={:#x}",
            entry.owner().get(),
            entry
                .soname()
                .map(|s| core::str::from_utf8(s.as_bytes()).unwrap_or("<non-utf8>"))
                .unwrap_or("-"),
            entry.load_bias().get()
        );
    }
    for (group, members) in plans.sccs().iter().enumerate() {
        log::info!(
            "LIFECYCLE_SCC group={} members={:?}",
            group,
            members.iter().map(|id| id.get()).collect::<alloc::vec::Vec<_>>()
        );
    }
}

/// C31-a scope oracle (§17.1): surface each relocation's frozen scope decision
/// — requester image id, symbol name and winning provider id — for the QEMU
/// checker to assert normalized binding triples.
fn log_bindings(product: &LinkProduct<KernelLinkReceipt>) {
    for binding in product.relocation_bindings() {
        let name = core::str::from_utf8(binding.name()).unwrap_or("<non-utf8>");
        match binding.provider() {
            Some(provider) => log::info!(
                "SCOPE_BIND requester={} name={} provider={}",
                binding.requester().get(),
                name,
                provider.get()
            ),
            None => log::info!(
                "SCOPE_BIND requester={} name={} provider=none",
                binding.requester().get(),
                name
            ),
        }
    }
}
