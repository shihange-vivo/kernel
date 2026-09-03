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
    dynamic_linker::{
        graph::{DependencyGraph, DiscoveryItem, DiscoveryQueue},
        ArtifactIdentity, ArtifactResolver, ArtifactRole, DependencyRequest, ImageId, LinkDomainId,
        ResolvedArtifact, RuntimeImageState, ScopeSet, SymbolTable,
    },
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    identity::{
        LoadLimits, LoadPolicy, LoadProfile, LoadRequest, SessionLimits, PHASE05_LOAD_POLICY,
    },
    image::{absorb_into_session, ImageLoader},
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
/// `S` is one of [`BuildingState`] or [`ScopedState`] (and, in C16/C17,
/// relocated/sealed states). The session owns the dependency graph, the
/// rollback log, the session budgets and metrics; the trusted [`LoadProfile`]
/// and [`LoadPolicy`] are carried so each absorbed image reuses the same
/// profile without re-deriving it.
pub(crate) struct LinkSession<'a, M: ImageMemory + ?Sized, S> {
    rollback: RollbackGuard<'a, M>,
    graph: DependencyGraph,
    limits: SessionLimits,
    metrics: LoadMetrics,
    profile: LoadProfile,
    policy: LoadPolicy,
    domain: LinkDomainId,
    state: S,
}

pub(crate) type BuildingSession<'a, M> = LinkSession<'a, M, BuildingState>;
pub(crate) type ScopedSession<'a, M> = LinkSession<'a, M, ScopedState>;

/// Phase 0.5 entry point (§10.2): a trusted profile, a session budget and the
/// single [`ArchRelocator`] used by every image in the link.
pub(crate) struct DynamicLinker<A> {
    arch: A,
    policy: LoadPolicy,
}

impl<A: ArchRelocator> DynamicLinker<A> {
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
    ) -> LoadResult<BuildingSession<'a, Memory>>
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
            state: BuildingState {
                images,
                discovery,
                closed: false,
            },
        })
    }
}

impl<'a, M: ImageMemory + ?Sized> BuildingSession<'a, M> {
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
    pub fn freeze_scopes(self) -> LoadResult<ScopedSession<'a, M>> {
        let LinkSession {
            rollback,
            graph,
            limits,
            metrics,
            profile,
            policy,
            domain,
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
            state: ScopedState { images, scopes },
        })
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
