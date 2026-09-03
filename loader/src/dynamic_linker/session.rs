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
    cache::{CacheSyncOutcome, CodeCache},
    dynamic_linker::{
        graph::{DependencyGraph, DiscoveryItem, DiscoveryQueue},
        lifecycle::{self, FiniPlan, InitPlan, LifecycleImage},
        publish::{
            self, CommittedImage, CommittingLinkProduct, LinkContext, LinkMapImage, LinkProduct,
            LinkPublisher, PreparedLinkManifest,
        },
        relocate::{self, RelocationImage, RelocationPolicy},
        ArtifactIdentity, ArtifactResolver, ArtifactRole, DependencyName, DependencyRequest,
        ImageId, ImageOwnership, LinkDomainId, PublishedImageDescriptor, ResolvedArtifact,
        RuntimeImageMetadata, RuntimeImageState, ScopeSet, SymbolTable,
    },
    elf::LoadSegmentInfo,
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    identity::{
        ElfType, LoadLimits, LoadPolicy, LoadProfile, LoadRequest, SessionLimits,
        PHASE05_LOAD_POLICY,
    },
    image::{
        absorb_into_session, AppliedProtectionSet, ImageLoader, LoadedRegion,
        PreparedProtectionPlan, ProtectionBatch, SealPlan, SealedState,
    },
    memory::{AllocationRollbackLog, ImageMemory, ImageProtectionMemory, SessionAllocation},
    reader::ElfReader,
    relocation::ArchRelocator,
};

/// Session metrics (§14.3). Only the counters this commit actually drives are
/// updated; symbol/lookup/relocation/protection/cache counters fill in with
/// C16/C17, whose stages consume the values they record.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoadMetrics {
    resolver_calls: u64,
    images: u64,
    edges: u64,
    max_depth: u16,
    symbol_lookups: u64,
    hash_probes: u64,
    relocation_operations: u64,
    protection_ranges: u64,
    cache_ranges: u64,
    image_bytes: u64,
    runtime_metadata_bytes: u64,
}

impl LoadMetrics {
    #[inline]
    pub(crate) fn record_resolver_call(&mut self) {
        self.resolver_calls += 1;
    }

    #[inline]
    pub(crate) fn record_image(
        &mut self,
        depth: u16,
        image_bytes: u64,
        metadata_bytes: u64,
        limits: &SessionLimits,
    ) -> LoadResult<()> {
        let total_image_bytes = self
            .image_bytes
            .checked_add(image_bytes)
            .ok_or_else(session_overflow)?;
        let total_metadata_bytes = self
            .runtime_metadata_bytes
            .checked_add(metadata_bytes)
            .ok_or_else(session_overflow)?;
        limits.check_total_image_bytes(total_image_bytes)?;
        limits.check_total_runtime_metadata_bytes(total_metadata_bytes)?;
        self.images += 1;
        self.max_depth = self.max_depth.max(depth);
        self.image_bytes = total_image_bytes;
        self.runtime_metadata_bytes = total_metadata_bytes;
        Ok(())
    }

    #[inline]
    pub(crate) fn record_edge(&mut self) {
        self.edges += 1;
    }

    #[inline]
    pub(crate) fn record_symbol_lookup(&mut self, limits: &SessionLimits) -> LoadResult<()> {
        let next = self
            .symbol_lookups
            .checked_add(1)
            .ok_or_else(session_overflow)?;
        limits.check_symbol_lookups(next)?;
        self.symbol_lookups = next;
        Ok(())
    }

    #[inline]
    pub(crate) fn record_hash_probes(&mut self, count: u64) {
        self.hash_probes = self.hash_probes.saturating_add(count);
    }

    #[inline]
    pub(crate) fn record_relocation_operation(&mut self) {
        self.relocation_operations += 1;
    }

    #[inline]
    pub(crate) fn record_protection_ranges(&mut self, count: usize) {
        self.protection_ranges = self.protection_ranges.saturating_add(count as u64);
    }

    #[inline]
    pub(crate) fn record_cache_ranges(&mut self, count: usize) {
        self.cache_ranges = self.cache_ranges.saturating_add(count as u64);
    }

    #[inline]
    pub const fn resolver_calls(&self) -> u64 {
        self.resolver_calls
    }

    #[inline]
    pub const fn images(&self) -> u64 {
        self.images
    }

    #[inline]
    pub const fn edges(&self) -> u64 {
        self.edges
    }

    #[inline]
    pub const fn max_depth(&self) -> u16 {
        self.max_depth
    }

    #[inline]
    pub const fn symbol_lookups(&self) -> u64 {
        self.symbol_lookups
    }

    #[inline]
    pub const fn hash_probes(&self) -> u64 {
        self.hash_probes
    }

    #[inline]
    pub const fn relocation_operations(&self) -> u64 {
        self.relocation_operations
    }

    #[inline]
    pub const fn protection_ranges(&self) -> u64 {
        self.protection_ranges
    }

    #[inline]
    pub const fn cache_ranges(&self) -> u64 {
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
pub struct BuildingState {
    images: Vec<SessionImage<RuntimeImageState>>,
    discovery: DiscoveryQueue,
    closed: bool,
    poisoned: bool,
}

/// Immutable session state once scopes are frozen (S6).
pub struct ScopedState {
    images: Vec<SessionImage<RuntimeImageState>>,
    scopes: ScopeSet,
}

/// Owned runtime state after session-wide relocation (S7). Relocation only
/// rewrites memory; the decoded metadata, load regions and segments are
/// unchanged, so this newtypes the decoded state to make a second relocation
/// unrepresentable.
pub struct RelocatedImageState(RuntimeImageState);

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
pub struct RelocatedState {
    images: Vec<SessionImage<RelocatedImageState>>,
    scopes: ScopeSet,
}

/// Per-image state after cache synchronization and memory protection (S8).
pub struct SealedImageState {
    runtime: RuntimeImageState,
    sealed: SealedState,
}

impl SealedImageState {
    #[inline]
    pub(crate) fn regions(&self) -> &[LoadedRegion] {
        self.runtime.regions()
    }

    #[inline]
    pub(crate) fn load_segments(&self) -> &[LoadSegmentInfo] {
        self.runtime.load_segments()
    }

    #[inline]
    pub(crate) const fn metadata(&self) -> &RuntimeImageMetadata {
        self.runtime.metadata()
    }

    #[inline]
    pub(crate) const fn load_bias(&self) -> TargetAddress {
        self.runtime.load_bias()
    }

    #[inline]
    pub(crate) const fn runtime_entry(&self) -> TargetAddress {
        self.runtime.runtime_entry()
    }
}

/// Immutable session state once every image has crossed the S8 cache and
/// protection boundary.
pub struct SealedSessionState {
    images: Vec<SessionImage<SealedImageState>>,
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
pub struct LinkSession<'a, M: ImageMemory + ?Sized, S, A> {
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

pub type BuildingSession<'a, M, A> = LinkSession<'a, M, BuildingState, A>;
pub type ScopedSession<'a, M, A> = LinkSession<'a, M, ScopedState, A>;
pub type RelocatedSession<'a, M, A> = LinkSession<'a, M, RelocatedState, A>;
pub type SealedSession<'a, M, A> = LinkSession<'a, M, SealedSessionState, A>;

/// Phase 0.5 entry point (§10.2): a trusted profile, a session budget and the
/// single [`ArchRelocator`] used by every image in the link.
pub struct DynamicLinker<A> {
    arch: A,
    policy: LoadPolicy,
}

impl<A: ArchRelocator> DynamicLinker<A> {
    pub fn new(arch: A) -> Self {
        Self {
            arch,
            policy: PHASE05_LOAD_POLICY,
        }
    }

    /// Run a complete link in one call: admit the root, close the dependency
    /// closure, freeze scopes, relocate, seal, and publish.
    ///
    /// This is the convenience wrapper over the staged API; it consumes the
    /// linker because the single [`ArchRelocator`] is moved through every
    /// session transition (§10.2). The `memory` backend must support protection
    /// (`ImageProtectionMemory`) so the session can reach the seal stage.
    pub fn link<R, Resolver, Memory, Cache, Publisher>(
        self,
        root: ResolvedArtifact<R>,
        profile: LoadProfile,
        domain: LinkDomainId,
        limits: SessionLimits,
        resolver: &mut Resolver,
        memory: &mut Memory,
        cache: &mut Cache,
        publisher: &mut Publisher,
    ) -> LoadResult<LinkProduct<Publisher::Receipt>>
    where
        R: ElfReader,
        Resolver: ArtifactResolver,
        Memory: ImageProtectionMemory + ?Sized,
        Cache: CodeCache + ?Sized,
        Publisher: LinkPublisher,
    {
        let mut building = self.begin(root, profile, domain, limits, memory)?;
        building.close_dependencies(resolver)?;
        building
            .freeze_scopes()?
            .relocate()?
            .seal(cache)?
            .publish(publisher)
    }

    /// Admit the root and open a building session.
    ///
    /// The root is always an [`ArtifactRole::ExecutableRoot`]; its reader is
    /// consumed through S0–S4 and the resulting allocation lease is absorbed
    /// into the session rollback log before the session is returned.
    pub fn begin<R, Memory>(
        self,
        root: ResolvedArtifact<R>,
        profile: LoadProfile,
        domain: LinkDomainId,
        limits: SessionLimits,
        memory: &mut Memory,
    ) -> LoadResult<BuildingSession<'_, Memory, A>>
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
        // The Phase 0.5 link root is always an allocated `ET_DYN` image owned by
        // this session: a fixed `ET_EXEC` stays on the Phase 0 single-image path,
        // and a system-candidate root would let an application reserve system
        // symbol space it cannot own (§12.1).
        if profile.r#type() != ElfType::Dyn {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::HeaderField {
                    field: crate::error::HeaderField::Type,
                    value: u64::from(profile.r#type()),
                },
            )
            .at_stage(LoadStage::Beginning));
        }
        if root.ownership() != ImageOwnership::SessionPrivate {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            )
            .at_stage(LoadStage::Beginning));
        }

        let mut guard = RollbackGuard {
            memory,
            log: AllocationRollbackLog::new(),
        };
        let mut graph = DependencyGraph::new(limits);
        let mut metrics = LoadMetrics::default();

        let (artifact, ownership, reader) = root.into_parts();
        let (allocation, mut runtime) = load_runtime(
            reader,
            profile,
            ArtifactRole::ExecutableRoot,
            self.policy,
            limits.per_image(),
            &mut guard.log,
            &mut *guard.memory,
        )?;

        let soname = runtime.take_soname();
        let metadata_bytes = session_image_metadata_bytes(&runtime, &artifact, soname.as_ref())?;
        let root_id = graph.insert_root(artifact, soname, ownership)?;
        validate_session_symbol_names(&runtime, &limits)?;
        metrics
            .record_image(0, allocation.allocation().len(), metadata_bytes, &limits)
            .map_err(|error| error.at_stage(LoadStage::Beginning))?;

        let mut images = Vec::new();
        images
            .try_reserve(1)
            .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
        images.push(SessionImage {
            image_id: root_id,
            allocation,
            state: runtime,
        });

        let mut discovery = DiscoveryQueue::new(limits);
        enqueue_dependencies(
            &mut discovery,
            root_id,
            images[0].state.metadata().needed(),
            &limits,
            LoadStage::Beginning,
        )?;

        Ok(LinkSession {
            rollback: guard,
            graph,
            limits,
            metrics,
            profile,
            policy: self.policy,
            domain,
            arch: self.arch,
            state: BuildingState {
                images,
                discovery,
                closed: false,
                poisoned: false,
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
        if self.state.poisoned {
            return Err(session_error(LoadErrorKind::BadElf, ErrorContext::None)
                .at_stage(LoadStage::Discover));
        }
        if self.state.closed {
            return Ok(());
        }

        let result = self.close_dependencies_inner(resolver);
        if result.is_err() {
            self.state.poisoned = true;
        }
        result
    }

    fn close_dependencies_inner<Resolver: ArtifactResolver>(
        &mut self,
        resolver: &mut Resolver,
    ) -> LoadResult<()> {
        while let Some(item) = self.state.discovery.pop() {
            let requester = item.requester();
            self.metrics.record_resolver_call();
            let resolved = {
                let requester_artifact = self
                    .graph
                    .node(requester)
                    .map(|node| node.artifact())
                    .ok_or_else(|| session_error(LoadErrorKind::BadElf, ErrorContext::None))?;
                let needed = needed_for(&self.state.images, requester, item.needed_index())?;
                let request = DependencyRequest::new(requester_artifact, needed, self.domain);
                resolver
                    .resolve(&request)
                    .map_err(|error| error.at_stage(LoadStage::Discover))?
            };

            let (identity, ownership, reader) = resolved.into_parts();

            // Identity de-duplication happens before any allocation (§5.3 rule 1).
            if let Some(existing) = self.graph.find_identity(&identity) {
                self.graph
                    .link_existing(requester, existing, item.needed_index())
                    .map_err(|error| error.at_stage(LoadStage::Discover))?;
                self.metrics.record_edge();
                continue;
            }

            let (allocation, mut runtime) = load_runtime(
                reader,
                self.profile,
                ArtifactRole::SharedObject,
                self.policy,
                self.limits.per_image(),
                &mut self.rollback.log,
                &mut *self.rollback.memory,
            )
            .map_err(|error| error.at_stage(LoadStage::Discover))?;

            let soname = runtime.take_soname();
            let metadata_bytes =
                session_image_metadata_bytes(&runtime, &identity, soname.as_ref())?;
            let needed = needed_for(&self.state.images, requester, item.needed_index())?;
            let provider = self
                .graph
                .insert_dependency(
                    requester,
                    needed,
                    item.needed_index(),
                    identity,
                    soname,
                    ownership,
                )
                .map_err(|error| error.at_stage(LoadStage::Discover))?;

            let depth = self
                .graph
                .node(provider)
                .map(|node| node.depth())
                .unwrap_or(0);
            validate_session_symbol_names(&runtime, &self.limits)
                .map_err(|error| error.at_stage(LoadStage::Discover))?;
            self.metrics
                .record_image(
                    depth,
                    allocation.allocation().len(),
                    metadata_bytes,
                    &self.limits,
                )
                .map_err(|error| error.at_stage(LoadStage::Discover))?;
            self.metrics.record_edge();

            enqueue_dependencies(
                &mut self.state.discovery,
                provider,
                runtime.metadata().needed(),
                &self.limits,
                LoadStage::Discover,
            )?;

            self.state.images.try_reserve(1).map_err(|_| {
                LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
                    .at_stage(LoadStage::Discover)
            })?;
            self.state.images.push(SessionImage {
                image_id: provider,
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
            poisoned,
        } = state;

        if !closed || poisoned {
            return Err(LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
                .at_stage(LoadStage::Scope));
        }

        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(images.len())
            .map_err(|_| scope_session_oom())?;
        for image in &images {
            symbols.push(image.state.metadata().symbols());
        }
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
        let image_count = self.state.images.len();
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(image_count)
            .map_err(|_| link_relocation_oom())?;
        let mut relocation_images = Vec::new();
        relocation_images
            .try_reserve_exact(image_count)
            .map_err(|_| link_relocation_oom())?;
        let mut relocated_images = Vec::new();
        relocated_images
            .try_reserve_exact(image_count)
            .map_err(|_| link_relocation_oom())?;
        for image in &self.state.images {
            symbols.push(image.state.metadata().symbols());
            relocation_images.push(RelocationImage::new(
                image.image_id,
                image.allocation,
                image.state.regions(),
                image.state.load_segments(),
                image.state.metadata(),
                image.state.load_bias(),
            ));
        }

        let policy = RelocationPolicy::for_profile(&self.profile);
        relocate::run(
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

        drop(relocation_images);
        drop(symbols);

        // Rewrap the decoded state so a second relocation is unrepresentable.
        for image in self.state.images {
            relocated_images.push(SessionImage {
                image_id: image.image_id,
                allocation: image.allocation,
                state: RelocatedImageState(image.state),
            });
        }
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
            state: RelocatedState {
                images: relocated_images,
                scopes,
            },
        })
    }
}

impl<'a, M: ImageProtectionMemory + ?Sized, A: ArchRelocator> RelocatedSession<'a, M, A> {
    /// Complete the session-wide cache and protection boundary (S8).
    ///
    /// Every logical seal plan, backend protection plan and executable range
    /// is prepared before the first cache/protection mutation. Publication is
    /// available only on the returned [`SealedSession`].
    pub fn seal<C: CodeCache + ?Sized>(
        mut self,
        cache: &mut C,
    ) -> LoadResult<SealedSession<'a, M, A>> {
        let image_count = self.state.images.len();
        let total_executable_ranges =
            self.state.images.iter().try_fold(0usize, |total, image| {
                let count = image
                    .state
                    .load_segments()
                    .iter()
                    .filter(|segment| {
                        segment
                            .permissions()
                            .contains(crate::MemoryPermissions::EXECUTE)
                            && segment.memory_size() != 0
                    })
                    .count();
                total.checked_add(count).ok_or_else(|| {
                    session_error(LoadErrorKind::IntegerOverflow, ErrorContext::None)
                        .at_stage(LoadStage::LinkSeal)
                })
            })?;

        let mut executable_ranges = Vec::new();
        executable_ranges
            .try_reserve_exact(total_executable_ranges)
            .map_err(|_| link_seal_oom())?;
        let mut prepared_seals = Vec::new();
        prepared_seals
            .try_reserve_exact(image_count)
            .map_err(|_| link_seal_oom())?;
        let mut sealed_images = Vec::new();
        sealed_images
            .try_reserve_exact(image_count)
            .map_err(|_| link_seal_oom())?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(image_count)
            .map_err(|_| link_seal_oom())?;

        for image in &self.state.images {
            let runtime = &image.state.0;
            let allocation = image.allocation.allocation();
            let seal_plan = SealPlan::build(
                &allocation,
                runtime.load_bias(),
                self.profile.class(),
                runtime.load_segments(),
                runtime.regions(),
                runtime.relro(),
                runtime.stack(),
                runtime.metadata().relocations().records(),
            )
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
            let prepared = PreparedProtectionPlan::prepare_for_allocation(
                &*self.rollback.memory,
                &allocation,
                &seal_plan,
            )
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;

            let executable_count = runtime
                .load_segments()
                .iter()
                .filter(|segment| {
                    segment
                        .permissions()
                        .contains(crate::MemoryPermissions::EXECUTE)
                        && segment.memory_size() != 0
                })
                .count();
            let mut image_executable_ranges = Vec::new();
            image_executable_ranges
                .try_reserve_exact(executable_count)
                .map_err(|_| link_seal_oom())?;
            for (segment, region) in runtime.load_segments().iter().zip(runtime.regions().iter()) {
                if segment
                    .permissions()
                    .contains(crate::MemoryPermissions::EXECUTE)
                    && !region.runtime_range().is_empty()
                {
                    image_executable_ranges.push(region.runtime_range());
                    executable_ranges.push(region.runtime_range());
                }
            }
            prepared_seals.push((seal_plan, prepared, image_executable_ranges));
        }

        let requirements = cache.requirements();
        let prepared_cache = cache
            .prepare(&executable_ranges)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        requirements
            .validate_prepared(&executable_ranges, &prepared_cache)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        let cache_scope = prepared_cache.scope();
        let cache_maintenance = prepared_cache.maintenance();
        let cache_sync = cache
            .synchronize(prepared_cache)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        cache_sync
            .validate_completion(&executable_ranges, cache_scope, cache_maintenance)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        self.metrics.record_cache_ranges(executable_ranges.len());

        for (image, (seal_plan, prepared, image_executable_ranges)) in
            self.state.images.iter().zip(prepared_seals.into_iter())
        {
            let protection_count = prepared.ranges().len();
            let allocation = image.allocation.allocation();
            let mut protection_records = prepared.into_ranges();
            self.rollback
                .log
                .mark_protection_modified(image.allocation)
                .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
            self.rollback
                .memory
                .apply_protection(&allocation, ProtectionBatch::new(&mut protection_records))
                .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
            self.metrics.record_protection_ranges(protection_count);

            let image_cache_sync = CacheSyncOutcome::from_synchronized_ranges(
                image_executable_ranges,
                cache_scope,
                cache_maintenance,
            );
            sealed_images.push(SealedState::new(
                image.state.load_bias(),
                image.state.runtime_entry(),
                image.state.0.canonical_runtime_entry(),
                image_cache_sync,
                seal_plan,
                AppliedProtectionSet::new(protection_records),
            ));
        }

        let RelocatedState { images, scopes } = self.state;
        let mut images = images.into_iter();
        let mut sealed_states = sealed_images.into_iter();
        while let (Some(image), Some(sealed)) = (images.next(), sealed_states.next()) {
            output.push(SessionImage {
                image_id: image.image_id,
                allocation: image.allocation,
                state: SealedImageState {
                    runtime: image.state.0,
                    sealed,
                },
            });
        }

        Ok(LinkSession {
            rollback: self.rollback,
            graph: self.graph,
            limits: self.limits,
            metrics: self.metrics,
            profile: self.profile,
            policy: self.policy,
            domain: self.domain,
            arch: self.arch,
            state: SealedSessionState {
                images: output,
                scopes,
            },
        })
    }
}

impl<M: ImageMemory + ?Sized, A: ArchRelocator> SealedSession<'_, M, A> {
    /// Build the dependency-first init and reverse fini plans (§12.2).
    ///
    /// Reads the post-relocation init/fini array words back through the
    /// session memory backend and validates each non-sentinel function target
    /// against its owner's executable region (and Thumb bit on ARM). The plans
    /// only *name* targets — nothing here calls a constructor.
    pub fn build_lifecycle_plans(&self) -> LoadResult<(InitPlan, FiniPlan)> {
        let mut images = Vec::new();
        images
            .try_reserve_exact(self.state.images.len())
            .map_err(|_| link_seal_oom())?;
        for image in &self.state.images {
            images.push(LifecycleImage::new(
                image.image_id,
                image.allocation,
                image.state.regions(),
                image.state.load_segments(),
                image.state.metadata().lifecycle(),
                image.state.load_bias(),
            ));
        }
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
        let mut images = Vec::new();
        images
            .try_reserve_exact(self.state.images.len())
            .map_err(|_| link_seal_oom())?;
        for image in &self.state.images {
            images.push(LinkMapImage::new(
                image.image_id,
                image.state.load_bias(),
                image.state.runtime_entry(),
                image.state.regions(),
            ));
        }
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
        self,
        publisher: &mut P,
    ) -> LoadResult<LinkProduct<P::Receipt>> {
        let (init_plan, fini_plan) = self.build_lifecycle_plans()?;
        let manifest = self.prepare_link_manifest()?;

        // One committed image per id: link-map facts plus the backing
        // allocation, in the same image-id order the leases are drained in.
        let mut committed = Vec::new();
        committed
            .try_reserve_exact(self.state.images.len())
            .map_err(|_| publish_oom())?;
        // Drain the unique leases in creation order (== image-id order).
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(self.rollback.log.len())
            .map_err(|_| publish_oom())?;

        let LinkSession {
            mut rollback,
            graph,
            limits: _,
            metrics,
            profile: _,
            policy: _,
            domain: _,
            arch: _,
            state,
        } = self;
        let SealedSessionState { images, scopes } = state;

        for image in images {
            let node = graph.node(image.image_id).ok_or_else(|| {
                LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
                    .at_stage(LoadStage::Publish)
            })?;
            let SealedImageState { runtime, sealed } = image.state;
            let (regions, load_segments, load_bias, program_headers, symbols) =
                runtime.into_publish_parts();
            let descriptor = PublishedImageDescriptor::from_node_and_state(
                node,
                image.allocation.allocation(),
                sealed,
                regions,
                load_segments,
                load_bias,
                program_headers,
                symbols,
            )
            .map_err(|error| error.at_stage(LoadStage::Publish))?;
            committed.push(CommittedImage::new(image.image_id, descriptor));
        }

        let context = LinkContext::new(graph, scopes, committed);
        let prepared = publisher
            .prepare_batch(&manifest)
            .map_err(|error| error.at_stage(LoadStage::Publish))?;
        let (entry, link_map) = manifest.into_parts();
        rollback.log.drain_leases_into(&mut leases);
        let product = CommittingLinkProduct::new(leases);

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

fn session_overflow() -> LoadError {
    session_error(LoadErrorKind::IntegerOverflow, ErrorContext::None)
}

fn validate_session_symbol_names(
    runtime: &RuntimeImageState,
    limits: &SessionLimits,
) -> LoadResult<()> {
    for entry in runtime.metadata().symbols().entries() {
        let len = u32::try_from(runtime.metadata().symbols().name(entry).len())
            .map_err(|_| session_error(LoadErrorKind::ResourceLimit, ErrorContext::None))?;
        limits.check_symbol_name_len(len)?;
    }
    Ok(())
}

fn session_image_metadata_bytes(
    runtime: &RuntimeImageState,
    identity: &ArtifactIdentity,
    soname: Option<&DependencyName>,
) -> LoadResult<u64> {
    runtime
        .metadata()
        .metadata_bytes()
        .checked_add(identity.metadata_bytes())
        .and_then(|bytes| bytes.checked_add(soname.map_or(0, |name| name.as_bytes().len() as u64)))
        .and_then(|bytes| {
            bytes.checked_add(
                runtime.load_segments().len() as u64
                    * core::mem::size_of::<LoadSegmentInfo>() as u64,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                runtime.regions().len() as u64 * core::mem::size_of::<LoadedRegion>() as u64,
            )
        })
        .ok_or_else(session_overflow)
}

fn needed_for(
    images: &[SessionImage<RuntimeImageState>],
    requester: ImageId,
    needed_index: u16,
) -> LoadResult<&DependencyName> {
    images
        .get(requester.get() as usize)
        .and_then(|image| {
            image
                .state
                .metadata()
                .needed()
                .get(usize::from(needed_index))
        })
        .ok_or_else(|| {
            session_error(LoadErrorKind::BadElf, ErrorContext::None).at_stage(LoadStage::Discover)
        })
}

fn enqueue_dependencies(
    queue: &mut DiscoveryQueue,
    requester: ImageId,
    needed: &[DependencyName],
    limits: &SessionLimits,
    stage: LoadStage,
) -> LoadResult<()> {
    for (index, name) in needed.iter().enumerate() {
        limits
            .check_dependency_name_len(name.as_bytes().len() as u32)
            .map_err(|error| error.at_stage(stage))?;
        let index = u16::try_from(index).map_err(|_| {
            session_error(LoadErrorKind::ResourceLimit, ErrorContext::None).at_stage(stage)
        })?;
        queue
            .push(DiscoveryItem::new(requester, index))
            .map_err(|error| error.at_stage(stage))?;
    }
    Ok(())
}

fn publish_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::Publish)
}

fn link_seal_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::LinkSeal)
}

fn link_relocation_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::LinkRelocate)
}

fn scope_session_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::Scope)
}
