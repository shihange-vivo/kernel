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

//! Staged link session typestate and rollback (S5–S6, §10).
//!
//! [`DynamicLinker::begin`] admits the root and absorbs it through the
//! single-image S0–S4 pipeline, transferring its allocation lease into the
//! session rollback log. [`close_dependencies`](BuildingSession::close_dependencies)
//! drives the bounded BFS closure, de-duplicating by identity before any new
//! allocation. [`freeze_scopes`](BuildingSession::freeze_scopes) consumes the
//! building session into an immutable [`ScopeSet`]. The `relocate`/`seal`
//! transitions are the C16/C17 seam and land with those commits.

use alloc::vec::Vec;

use crate::{
    address::TargetAddress,
    dynamic_linker::{
        graph::{DependencyGraph, DiscoveryItem, DiscoveryQueue},
        lifecycle::{self, FiniPlan, InitPlan, LifecycleImage},
        publish::{
            self, CommittedImage, CommittingLinkProduct, LinkContext, LinkMapImage, LinkProduct,
            LinkPublisher, PreparedLinkManifest,
        },
        relocate::{self, RelocationImage, RelocationPolicy},
        ArtifactIdentity, ArtifactResolver, ArtifactRole, DependencyRequest, ImageId, LinkDomainId,
        ResolvedArtifact, RuntimeImageMetadata, RuntimeImageState, ScopeSet, SymbolTable,
    },
    elf::LoadSegmentInfo,
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    identity::{
        LoadLimits, LoadPolicy, LoadProfile, LoadRequest, SessionLimits, PHASE05_LOAD_POLICY,
    },
    image::{absorb_into_session, ImageLoader, LoadedRegion},
    memory::{AllocationRollbackLog, ImageMemory, SessionAllocation},
    reader::ElfReader,
    relocation::ArchRelocator,
};

/// Session metrics (§14.3). Only the counters this commit actually drives are
/// updated; symbol/lookup/relocation/protection/cache counters fill in with
/// C16/C17, whose stages consume the values they record.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LoadMetrics {
    resolver_calls: u64,
    images: u64,
    edges: u64,
    max_depth: u16,
    symbol_lookups: u64,
    hash_probes: u64,
    relocation_operations: u64,
    protection_ranges: u64,
    cache_ranges: u64,
}

impl LoadMetrics {
    #[inline]
    pub(crate) fn record_resolver_call(&mut self) {
        self.resolver_calls += 1;
    }

    #[inline]
    pub(crate) fn record_image(&mut self, depth: u16) {
        self.images += 1;
        self.max_depth = self.max_depth.max(depth);
    }

    #[inline]
    pub(crate) fn record_edge(&mut self) {
        self.edges += 1;
    }

    #[inline]
    pub(crate) fn record_symbol_lookup(&mut self) {
        self.symbol_lookups += 1;
    }

    #[inline]
    pub(crate) fn record_hash_probe(&mut self) {
        self.hash_probes += 1;
    }

    #[inline]
    pub(crate) fn record_relocation_operation(&mut self) {
        self.relocation_operations += 1;
    }

    #[inline]
    pub(crate) const fn resolver_calls(&self) -> u64 {
        self.resolver_calls
    }

    #[inline]
    pub(crate) const fn images(&self) -> u64 {
        self.images
    }

    #[inline]
    pub(crate) const fn edges(&self) -> u64 {
        self.edges
    }

    #[inline]
    pub(crate) const fn max_depth(&self) -> u16 {
        self.max_depth
    }

    #[inline]
    pub(crate) const fn symbol_lookups(&self) -> u64 {
        self.symbol_lookups
    }

    #[inline]
    pub(crate) const fn hash_probes(&self) -> u64 {
        self.hash_probes
    }

    #[inline]
    pub(crate) const fn relocation_operations(&self) -> u64 {
        self.relocation_operations
    }

    #[inline]
    pub(crate) const fn protection_ranges(&self) -> u64 {
        self.protection_ranges
    }

    #[inline]
    pub(crate) const fn cache_ranges(&self) -> u64 {
        self.cache_ranges
    }
}

/// One image admitted into the session, parameterized by its pipeline state.
///
/// `allocation` is a copyable descriptor plus an unforgeable rollback slot: it
/// can select the image for reads/writes but has no authority to abort or
/// commit the allocation. The unique lease lives only in the session rollback
/// log (§6.2).
pub(crate) struct SessionImage<S> {
    image_id: ImageId,
    artifact: ArtifactIdentity,
    allocation: SessionAllocation,
    state: S,
}

impl<S> SessionImage<S> {
    #[inline]
    pub(crate) const fn image_id(&self) -> ImageId {
        self.image_id
    }

    #[inline]
    pub(crate) const fn allocation(&self) -> SessionAllocation {
        self.allocation
    }

    #[inline]
    pub(crate) const fn state(&self) -> &S {
        &self.state
    }
}

/// Immutable session state while dependencies are being discovered (S5).
pub(crate) struct BuildingState {
    images: Vec<SessionImage<RuntimeImageState>>,
    discovery: DiscoveryQueue,
    closed: bool,
}

/// Immutable session state once scopes are frozen (S6).
pub(crate) struct ScopedState {
    images: Vec<SessionImage<RuntimeImageState>>,
    scopes: ScopeSet,
}

/// Owned runtime state after session-wide relocation (S7). Relocation only
/// rewrites memory; the decoded metadata, load regions and segments are
/// unchanged, so this newtypes the decoded state to make a second relocation
/// unrepresentable.
pub(crate) struct RelocatedImageState(RuntimeImageState);

impl RelocatedImageState {
    #[inline]
    pub(crate) fn regions(&self) -> &[LoadedRegion] {
        self.0.regions()
    }

    #[inline]
    pub(crate) fn load_segments(&self) -> &[LoadSegmentInfo] {
        self.0.load_segments()
    }

    #[inline]
    pub(crate) const fn metadata(&self) -> &RuntimeImageMetadata {
        self.0.metadata()
    }

    #[inline]
    pub(crate) const fn load_bias(&self) -> TargetAddress {
        self.0.load_bias()
    }

    #[inline]
    pub(crate) const fn runtime_entry(&self) -> TargetAddress {
        self.0.runtime_entry()
    }
}

/// Immutable session state once every image is relocated (S7).
pub(crate) struct RelocatedState {
    images: Vec<SessionImage<RelocatedImageState>>,
    scopes: ScopeSet,
}

/// The rollback authority for a live session: it owns the memory backend it
/// aborts against and the unique allocation leases absorbed so far.
///
/// This is separated from [`LinkSession`] so the session itself can move fields
/// in consuming transitions without Rust's move-out-of-`Drop` restriction, while
/// still guaranteeing reverse-order abort on any early exit.
struct RollbackGuard<'a, M: ImageMemory + ?Sized> {
    memory: &'a mut M,
    log: AllocationRollbackLog,
}

impl<M: ImageMemory + ?Sized> Drop for RollbackGuard<'_, M> {
    fn drop(&mut self) {
        self.log.abort_all(&mut *self.memory);
    }
}

/// A staged, multi-image link session (§10).
///
/// `S` is one of [`BuildingState`], [`ScopedState`] or [`RelocatedState`]
/// (and, in C17, a sealed state). The session owns the dependency graph, the
/// rollback log, the session budgets and metrics; the trusted [`LoadProfile`],
/// [`LoadPolicy`] and the single [`ArchRelocator`] are carried so every image
/// reuses the same profile and relocation semantics without re-deriving them.
pub(crate) struct LinkSession<'a, M: ImageMemory + ?Sized, S, A> {
    rollback: RollbackGuard<'a, M>,
    graph: DependencyGraph,
    limits: SessionLimits,
    metrics: LoadMetrics,
    profile: LoadProfile,
    policy: LoadPolicy,
    domain: LinkDomainId,
    arch: A,
    state: S,
}

pub(crate) type BuildingSession<'a, M, A> = LinkSession<'a, M, BuildingState, A>;
pub(crate) type ScopedSession<'a, M, A> = LinkSession<'a, M, ScopedState, A>;
pub(crate) type RelocatedSession<'a, M, A> = LinkSession<'a, M, RelocatedState, A>;

/// Phase 0.5 entry point (§10.2): a trusted profile, a session budget and the
/// single [`ArchRelocator`] used by every image in the link.
pub(crate) struct DynamicLinker<A> {
    arch: A,
    policy: LoadPolicy,
}

impl<A: ArchRelocator + Clone> DynamicLinker<A> {
    pub(crate) fn new(arch: A) -> Self {
        Self {
            arch,
            policy: PHASE05_LOAD_POLICY,
        }
    }

    /// Admit the root and open a building session.
    ///
    /// The root is always an [`ArtifactRole::ExecutableRoot`]; its reader is
    /// consumed through S0–S4 and the resulting allocation lease is absorbed
    /// into the session rollback log before the session is returned.
    pub fn begin<'a, R, Memory>(
        &self,
        root: ResolvedArtifact<R>,
        profile: LoadProfile,
        domain: LinkDomainId,
        limits: SessionLimits,
        memory: &'a mut Memory,
    ) -> LoadResult<BuildingSession<'a, Memory, A>>
    where
        R: ElfReader,
        Memory: ImageMemory + ?Sized,
    {
        if self.arch.machine() != profile.machine() || self.arch.class() != profile.class() {
            return Err(
                LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
                    .at_stage(LoadStage::Beginning),
            );
        }

        let mut guard = RollbackGuard {
            memory,
            log: AllocationRollbackLog::new(),
        };
        let mut graph = DependencyGraph::new(limits);
        let mut metrics = LoadMetrics::default();

        let artifact = root.identity().clone();
        let ownership = root.ownership();
        let (allocation, runtime) = load_runtime(
            root.into_reader(),
            profile,
            ArtifactRole::ExecutableRoot,
            self.policy,
            limits.per_image(),
            &mut guard.log,
            &mut *guard.memory,
        )?;

        let soname = runtime.metadata().soname().cloned();
        let root_id = graph.insert_root(artifact.clone(), soname, ownership)?;
        metrics.record_image(0);

        let mut images = Vec::new();
        images
            .try_reserve(1)
            .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
        images.push(SessionImage {
            image_id: root_id,
            artifact,
            allocation,
            state: runtime,
        });

        let mut discovery = DiscoveryQueue::new(limits);
        for (index, name) in images[0].state.metadata().needed().iter().enumerate() {
            discovery.push(DiscoveryItem::new(root_id, name.clone(), index as u16))?;
        }

        Ok(LinkSession {
            rollback: guard,
            graph,
            limits,
            metrics,
            profile,
            policy: self.policy,
            domain,
            arch: self.arch.clone(),
            state: BuildingState {
                images,
                discovery,
                closed: false,
            },
        })
    }
}

impl<'a, M: ImageMemory + ?Sized, A: ArchRelocator> BuildingSession<'a, M, A> {
    /// Drive the bounded BFS closure until the discovery queue is empty.
    ///
    /// Each resolved dependency is de-duplicated by identity *before* it is
    /// loaded; an already-loaded provider only records an extra edge (§8.2 rule
    /// 6). A new artifact runs the S0–S4 pipeline, is absorbed into the session
    /// rollback log, and its own `DT_NEEDED` are enqueued in encounter order.
    pub fn close_dependencies<Resolver: ArtifactResolver>(
        &mut self,
        resolver: &mut Resolver,
    ) -> LoadResult<()> {
        if self.state.closed {
            return Ok(());
        }

        while let Some(item) = self.state.discovery.pop() {
            let requester = item.requester();
            let requester_artifact = self
                .graph
                .node(requester)
                .map(|node| node.artifact().clone())
                .ok_or_else(|| session_error(LoadErrorKind::BadElf, ErrorContext::None))?;
            let request =
                DependencyRequest::new(requester_artifact, item.needed().clone(), self.domain);

            self.metrics.record_resolver_call();
            let resolved = resolver
                .resolve(&request)
                .map_err(|error| error.at_stage(LoadStage::Discover))?;

            let identity = resolved.identity().clone();
            let ownership = resolved.ownership();

            // Identity de-duplication happens before any allocation (§5.3 rule 1).
            if let Some(existing) = self.graph.find_identity(&identity) {
                self.graph
                    .link_existing(requester, existing, item.needed_index())
                    .map_err(|error| error.at_stage(LoadStage::Discover))?;
                self.metrics.record_edge();
                continue;
            }

            let (allocation, runtime) = load_runtime(
                resolved.into_reader(),
                self.profile,
                ArtifactRole::SharedObject,
                self.policy,
                self.limits.per_image(),
                &mut self.rollback.log,
                &mut *self.rollback.memory,
            )
            .map_err(|error| error.at_stage(LoadStage::Discover))?;

            let soname = runtime.metadata().soname().cloned();
            let provider = self
                .graph
                .insert_dependency(
                    requester,
                    item.needed(),
                    item.needed_index(),
                    identity.clone(),
                    soname,
                    ownership,
                )
                .map_err(|error| error.at_stage(LoadStage::Discover))?;

            let depth = self
                .graph
                .node(provider)
                .map(|node| node.depth())
                .unwrap_or(0);
            self.metrics.record_image(depth);
            self.metrics.record_edge();

            for (index, name) in runtime.metadata().needed().iter().enumerate() {
                self.state
                    .discovery
                    .push(DiscoveryItem::new(provider, name.clone(), index as u16))
                    .map_err(|error| error.at_stage(LoadStage::Discover))?;
            }

            self.state.images.try_reserve(1).map_err(|_| {
                LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
                    .at_stage(LoadStage::Discover)
            })?;
            self.state.images.push(SessionImage {
                image_id: provider,
                artifact: identity,
                allocation,
                state: runtime,
            });
        }

        self.state.closed = true;
        Ok(())
    }

    /// Freeze the closed dependency graph into an immutable [`ScopeSet`].
    ///
    /// Consumes the building session; on any error the session is dropped and
    /// every absorbed allocation is aborted in reverse creation order.
    pub fn freeze_scopes(self) -> LoadResult<ScopedSession<'a, M, A>> {
        let LinkSession {
            rollback,
            graph,
            limits,
            metrics,
            profile,
            policy,
            domain,
            arch,
            state,
        } = self;
        let BuildingState {
            images,
            discovery: _,
            closed,
        } = state;

        if !closed {
            return Err(LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
                .at_stage(LoadStage::Scope));
        }

        let symbols: Vec<&SymbolTable> = images
            .iter()
            .map(|image| image.state.metadata().symbols())
            .collect();
        let scopes =
            ScopeSet::freeze(&graph, &symbols).map_err(|error| error.at_stage(LoadStage::Scope))?;

        Ok(LinkSession {
            rollback,
            graph,
            limits,
            metrics,
            profile,
            policy,
            domain,
            arch,
            state: ScopedState { images, scopes },
        })
    }
}

impl<'a, M: ImageMemory + ?Sized, A: ArchRelocator> ScopedSession<'a, M, A> {
    /// Run the session-wide relocation (S7, §11).
    ///
    /// Consumes the scoped session; every decoded relocation record is
    /// preflighted and applied against the frozen scopes. On any error the
    /// session is dropped and all absorbed allocations aborted.
    pub fn relocate(mut self) -> LoadResult<RelocatedSession<'a, M, A>> {
        let symbols: Vec<&SymbolTable> = self
            .state
            .images
            .iter()
            .map(|image| image.state.metadata().symbols())
            .collect();

        let relocation_images: Vec<RelocationImage<'_>> = self
            .state
            .images
            .iter()
            .map(|image| {
                RelocationImage::new(
                    image.image_id,
                    image.allocation,
                    image.state.regions(),
                    image.state.load_segments(),
                    image.state.metadata(),
                    image.state.load_bias(),
                )
            })
            .collect();

        let policy = RelocationPolicy::for_profile(&self.profile);
        let _operations = relocate::run(
            &self.arch,
            &symbols,
            &relocation_images,
            &self.state.scopes,
            &self.profile,
            &policy,
            &self.limits,
            &mut self.metrics,
            &mut *self.rollback.memory,
            &mut self.rollback.log,
        )
        .map_err(|error| error.at_stage(LoadStage::LinkRelocate))?;

        // Rewrap the decoded state so a second relocation is unrepresentable.
        let images = self
            .state
            .images
            .into_iter()
            .map(|image| SessionImage {
                image_id: image.image_id,
                artifact: image.artifact,
                allocation: image.allocation,
                state: RelocatedImageState(image.state),
            })
            .collect();
        let scopes = self.state.scopes;

        Ok(LinkSession {
            rollback: self.rollback,
            graph: self.graph,
            limits: self.limits,
            metrics: self.metrics,
            profile: self.profile,
            policy: self.policy,
            domain: self.domain,
            arch: self.arch,
            state: RelocatedState { images, scopes },
        })
    }
}

impl<M: ImageMemory + ?Sized, A: ArchRelocator> RelocatedSession<'_, M, A> {
    /// Build the dependency-first init and reverse fini plans (§12.2).
    ///
    /// Reads the post-relocation init/fini array words back through the
    /// session memory backend and validates each non-sentinel function target
    /// against its owner's executable region (and Thumb bit on ARM). The plans
    /// only *name* targets — nothing here calls a constructor.
    pub fn build_lifecycle_plans(&self) -> LoadResult<(InitPlan, FiniPlan)> {
        let images: Vec<LifecycleImage<'_>> = self
            .state
            .images
            .iter()
            .map(|image| {
                LifecycleImage::new(
                    image.image_id,
                    image.allocation,
                    image.state.regions(),
                    image.state.load_segments(),
                    image.state.metadata().lifecycle(),
                    image.state.load_bias(),
                )
            })
            .collect();
        lifecycle::build(&self.graph, &images, &self.profile, &*self.rollback.memory)
    }

    /// Build the prepared link manifest (link map + root entry) for atomic
    /// publication (§13.1).
    ///
    /// Emits one [`LinkMapEntry`] per relocated image in image-id order and
    /// uses the root's runtime entry computed during mapping. The
    /// result holds no lease: it is the pure description the host publisher
    /// validates in `prepare_batch` before the committed snapshot is swapped.
    pub fn prepare_link_manifest(&self) -> LoadResult<PreparedLinkManifest> {
        let images: Vec<LinkMapImage<'_>> = self
            .state
            .images
            .iter()
            .map(|image| {
                LinkMapImage::new(
                    image.image_id,
                    image.state.load_bias(),
                    image.state.runtime_entry(),
                    image.state.regions(),
                )
            })
            .collect();
        publish::build_manifest(&self.graph, &images)
    }

    /// Atomically publish the link product (S9, §13).
    ///
    /// Builds the lifecycle plans and the prepared manifest, lets the publisher
    /// complete every fallible check without mutating the visible snapshot,
    /// then moves the unique allocation leases out of the session rollback log
    /// into the publisher's committed owner in one infallible commit. On any
    /// `prepare_batch` failure the session drops and aborts every absorbed
    /// allocation; after a successful commit the rollback log is empty and the
    /// publisher's `Receipt` is the long-term owner of the committed images.
    pub fn publish<P: LinkPublisher>(
        mut self,
        publisher: &mut P,
    ) -> LoadResult<LinkProduct<P::Receipt>> {
        let (init_plan, fini_plan) = self.build_lifecycle_plans()?;
        let manifest = self.prepare_link_manifest()?;

        let prepared = publisher
            .prepare_batch(&manifest)
            .map_err(|error| error.at_stage(LoadStage::Publish))?;

        let (entry, link_map) = manifest.into_parts();

        // One committed image per id: link-map facts plus the backing
        // allocation, in the same image-id order the leases are drained in.
        let mut committed = Vec::new();
        committed
            .try_reserve_exact(self.state.images.len())
            .map_err(|_| publish_oom())?;
        for (image, map_entry) in self.state.images.iter().zip(link_map.iter()) {
            committed.push(CommittedImage::new(
                map_entry.clone(),
                image.allocation.allocation(),
            ));
        }

        // Drain the unique leases in creation order (== image-id order).
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(self.rollback.log.len())
            .map_err(|_| publish_oom())?;
        self.rollback.log.drain_leases_into(&mut leases);
        let product = CommittingLinkProduct::new(leases.into_boxed_slice());

        let LinkSession {
            rollback: _,
            graph,
            limits: _,
            metrics,
            profile: _,
            policy: _,
            domain: _,
            arch: _,
            state,
        } = self;
        let RelocatedState { images: _, scopes } = state;

        let context = LinkContext::new(graph, scopes, committed.into_boxed_slice());

        // SAFETY: `prepared` and `product` were produced by this same live
        // session; every fallible check completed before the leases moved.
        let receipt = unsafe { publisher.commit_batch(prepared, product) };

        Ok(LinkProduct::new(
            context, entry, init_plan, fini_plan, link_map, metrics, receipt,
        ))
    }
}

/// Run the single-image S0–S4 pipeline on `reader` under `profile`/`role`, then
/// transfer the resulting allocation lease into the session rollback log and
/// return the decoded runtime state.
fn load_runtime<R, Memory>(
    reader: R,
    profile: LoadProfile,
    role: ArtifactRole,
    policy: LoadPolicy,
    limits: &LoadLimits,
    rollback: &mut AllocationRollbackLog,
    memory: &mut Memory,
) -> LoadResult<(SessionAllocation, RuntimeImageState)>
where
    R: ElfReader,
    Memory: ImageMemory + ?Sized,
{
    let request = LoadRequest::new(profile, *limits);
    let decoded = ImageLoader::new(reader, request)
        .admit()?
        .inspect_with_policy(policy)
        .with_role(role)
        .inspect()?
        .plan()?
        .allocate(memory)?
        .map()?
        .decode_with_policy(policy)?;
    absorb_into_session(decoded, rollback)
}

fn session_error(kind: LoadErrorKind, context: ErrorContext) -> LoadError {
    LoadError::new(kind, context)
}

fn publish_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::Publish)
}
