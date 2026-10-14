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

//! Linking already materialized images: scope freezing, relocation, sealing
//! and publication. `loading` supplies the fixed graph and mapped inputs.
//! Each consuming transition keeps the allocation rollback guard armed.

use crate::image::{ArtifactRole, DependencyName, RuntimeImageState, SymbolTable};

use alloc::{sync::Arc, vec::Vec};

use crate::{
    dynamic_linker::{
        graph::DependencyGraph,
        lifecycle::{self, LifecycleImage, LifecyclePlans},
        publish::{
            self, CommittedImage, CommittingLinkProduct, LinkContext, LinkMapImage, LinkProduct,
            LinkPublisher, PreparedLinkManifest,
        },
        relocate::{self, ProviderRegion, RelocationImage, RelocationSource, RelocationTypeSet},
        scope::RelocationBinding,
        ImageDependency, ImageId, ImageOwnership, PublishedImageDescriptor, PublishedLoadSnapshot,
        ScopeSet,
    },
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::{PreparedProtectionPlan, ProtectionBatch, SealPlan},
    memory::{
        address::TargetAddress, cache::ArchitectureCodeCache, AllocationRollbackGuard, ImageMemory,
        ImageProtectionMemory, SessionAllocation,
    },
    profile::{LoadProfile, SessionLimits},
    relocation::ArchRelocator,
    LoadError, LoadResult,
};

/// Resource usage that must be accumulated across a link session to enforce
/// limits spanning more than one image or lookup.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SessionUsage {
    symbol_lookups: u64,
    image_bytes: u64,
    runtime_metadata_bytes: u64,
}

impl SessionUsage {
    #[inline]
    pub(crate) fn record_image(
        &mut self,
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
        self.image_bytes = total_image_bytes;
        self.runtime_metadata_bytes = total_metadata_bytes;
        Ok(())
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

    /// Charge the relocation-binding snapshot (name copies plus the
    /// fixed per-binding overhead) against the runtime metadata budget.
    #[inline]
    pub(crate) fn record_relocation_bindings(
        &mut self,
        bytes: u64,
        limits: &SessionLimits,
    ) -> LoadResult<()> {
        let total = self
            .runtime_metadata_bytes
            .checked_add(bytes)
            .ok_or_else(session_overflow)?;
        limits.check_total_runtime_metadata_bytes(total)?;
        self.runtime_metadata_bytes = total;
        Ok(())
    }
}

/// One image admitted into the session. The enclosing session type records
/// which loading and linking stages have completed.
///
/// `allocation` is a copyable descriptor plus an unforgeable rollback slot: it
/// can select the image for reads/writes but has no authority to abort or
/// commit the allocation. The unique lease lives only in the session rollback
/// log.
pub(crate) struct SessionImage {
    pub(crate) image_id: ImageId,
    pub(crate) role: ArtifactRole,
    pub(crate) allocation: SessionAllocation,
    pub(crate) state: RuntimeImageState,
}

/// One Ready system image imported from the registry instead of loaded.
///
/// It joins the dependency graph, the symbol scopes, the link map and the
/// committed context, but is never allocated, relocated, sealed or
/// re-initialized here — its unique lease lives in the system registry, not in
/// this session's rollback log. The owned descriptor supplies the export
/// surface and published regions the later stages read from.
pub(crate) struct ImportedImage {
    pub(crate) image_id: ImageId,
    pub(crate) descriptor: Arc<PublishedImageDescriptor>,
}

impl ImportedImage {
    #[inline]
    pub(crate) fn descriptor(&self) -> &PublishedImageDescriptor {
        self.descriptor.as_ref()
    }
}

/// A fixed dependency graph and all mapped or imported image inputs.
/// Dependency discovery and mapping are completed by `loading` before linking.
pub(crate) struct LoadedState {
    pub(crate) images: Vec<SessionImage>,
    pub(crate) imported: Vec<ImportedImage>,
    pub(crate) scope_prefix: Vec<ImageId>,
}

/// Immutable session state once scopes are frozen.
pub(crate) struct ScopedState {
    images: Vec<SessionImage>,
    imported: Vec<ImportedImage>,
    scopes: ScopeSet,
}

/// Immutable session state once every image is relocated.
pub(crate) struct RelocatedState {
    images: Vec<SessionImage>,
    imported: Vec<ImportedImage>,
    /// Recorded scope decision for each relocation.
    bindings: Vec<RelocationBinding>,
}

/// Immutable session state once every image has crossed the cache and
/// protection boundary.
pub(crate) struct SealedSessionState {
    images: Vec<SessionImage>,
    imported: Vec<ImportedImage>,
    /// Recorded scope decision for each relocation.
    bindings: Vec<RelocationBinding>,
}

/// A staged, multi-image link session.
///
/// `S` tracks loaded images, frozen scopes, relocation and sealing. The session
/// owns the dependency graph, rollback log and cross-image resource usage;
/// the trusted [`LoadProfile`] and single [`ArchRelocator`] ensure every image
/// reuses the same profile and relocation semantics without re-deriving them.
#[must_use = "dropping a link session aborts its allocations"]
pub(crate) struct LinkSession<'a, M: ImageMemory + ?Sized, S, A> {
    pub(crate) rollback: AllocationRollbackGuard<'a, M>,
    pub(crate) graph: DependencyGraph,
    pub(crate) limits: SessionLimits,
    pub(crate) usage: SessionUsage,
    pub(crate) profile: LoadProfile,
    pub(crate) arch: A,
    pub(crate) state: S,
}

pub(crate) type LoadedSession<'a, M, A> = LinkSession<'a, M, LoadedState, A>;
pub(crate) type ScopedSession<'a, M, A> = LinkSession<'a, M, ScopedState, A>;
pub(crate) type RelocatedSession<'a, M, A> = LinkSession<'a, M, RelocatedState, A>;
pub(crate) type SealedSession<'a, M, A> = LinkSession<'a, M, SealedSessionState, A>;

impl<'a, M: ImageMemory + ?Sized, A: ArchRelocator> LoadedSession<'a, M, A> {
    pub(crate) fn freeze_scopes(self) -> LoadResult<ScopedSession<'a, M, A>> {
        let LinkSession {
            rollback,
            graph,
            limits,
            usage,
            profile,
            arch,
            state,
        } = self;
        let LoadedState {
            images,
            imported,
            scope_prefix,
        } = state;

        // Freezing scopes only needs graph structure. Symbol tables are
        // indexed and checked when relocation consumes the frozen scope.
        let scopes = if scope_prefix.is_empty() {
            ScopeSet::freeze(&graph)
        } else {
            ScopeSet::freeze_with_prefix(&graph, &scope_prefix)
        }
        .map_err(|error| error.at_stage(LoadStage::Scope))?;

        Ok(LinkSession {
            rollback,
            graph,
            limits,
            usage,
            profile,
            arch,
            state: ScopedState {
                images,
                imported,
                scopes,
            },
        })
    }
}

impl<'a, M: ImageMemory + ?Sized, A: ArchRelocator> ScopedSession<'a, M, A> {
    /// Run the session-wide relocation.
    ///
    /// Consumes the scoped session; every decoded relocation record is
    /// preflighted and applied against the frozen scopes. On any error the
    /// session is dropped and all absorbed allocations aborted.
    pub(crate) fn relocate(mut self) -> LoadResult<RelocatedSession<'a, M, A>> {
        let image_count = self.state.images.len();
        let total_images = image_count + self.state.imported.len();
        // Both arrays are image-id indexed over every admitted image — loaded
        // and imported — because relocation resolves a symbol's owner
        // id back into them. `symbols` supplies each imported provider's
        // retained export table; `relocation_images` is `None` at an imported
        // id (an imported image contributes no relocation records and is never
        // rewritten), while `apply` indexes it by owner id.
        let mut symbol_slots: Vec<Option<&SymbolTable>> = Vec::new();
        symbol_slots
            .try_reserve_exact(total_images)
            .map_err(|_| link_relocation_oom())?;
        symbol_slots.resize_with(total_images, || None);
        let mut relocation_images: Vec<Option<RelocationImage<'_>>> = Vec::new();
        relocation_images
            .try_reserve_exact(total_images)
            .map_err(|_| link_relocation_oom())?;
        relocation_images.resize_with(total_images, || None);
        for image in &self.state.images {
            symbol_slots[image.image_id.get() as usize] = Some(image.state.metadata().symbols());
            relocation_images[image.image_id.get() as usize] = Some(RelocationImage::new(
                image.image_id,
                image.allocation,
                image.state.regions(),
                image.state.load_segments(),
                image.state.metadata(),
                image.state.load_bias(),
            ));
        }
        for imported in &self.state.imported {
            symbol_slots[imported.image_id.get() as usize] = Some(imported.descriptor().exports());
        }
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(total_images)
            .map_err(|_| link_relocation_oom())?;
        for slot in symbol_slots {
            symbols.push(slot.ok_or_else(|| {
                LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
                    .at_stage(LoadStage::LinkRelocate)
            })?);
        }
        // The provider-region array is image-id indexed over every admitted
        // image, loaded and imported, so a symbol resolved into an
        // imported provider is range-checked against the same facts a fresh
        // load would have produced.
        let mut provider_regions = Vec::new();
        provider_regions
            .try_reserve_exact(total_images)
            .map_err(|_| link_relocation_oom())?;
        provider_regions.resize_with(total_images, Vec::new);
        for image in &self.state.images {
            let regions = image
                .state
                .load_segments()
                .iter()
                .zip(image.state.regions().iter())
                .map(|(segment, region)| {
                    ProviderRegion::new(segment.permissions(), region.runtime_range())
                })
                .collect();
            provider_regions[image.image_id.get() as usize] = regions;
        }
        for imported in &self.state.imported {
            let regions = imported
                .descriptor()
                .regions()
                .iter()
                .map(|region| ProviderRegion::new(region.permissions(), region.runtime_range()))
                .collect();
            provider_regions[imported.image_id.get() as usize] = regions;
        }

        let policy = RelocationTypeSet::for_profile(&self.profile);
        let operations = relocate::run(
            &self.arch,
            &symbols,
            &relocation_images,
            &provider_regions,
            &self.state.scopes,
            &self.profile,
            &policy,
            &self.limits,
            &mut self.usage,
            &mut *self.rollback.memory,
            &mut self.rollback.log,
        )
        .map_err(|error| error.at_stage(LoadStage::LinkRelocate))?;

        // Record every relocation's scope decision:
        // requester, symbol name and winning provider — into the published
        // snapshot before moving into the next session state.
        let bindings = record_bindings(&operations, &symbols, &self.limits, &mut self.usage)?;

        drop(relocation_images);
        drop(symbols);

        let ScopedState {
            images,
            imported,
            scopes: _,
        } = self.state;
        // Consuming ScopedState prevents a second relocation; image storage
        // moves unchanged into the next session state.
        Ok(LinkSession {
            rollback: self.rollback,
            graph: self.graph,
            limits: self.limits,
            usage: self.usage,
            profile: self.profile,
            arch: self.arch,
            state: RelocatedState {
                images,
                imported,
                bindings,
            },
        })
    }
}

impl<'a, M: ImageProtectionMemory + ?Sized, A: ArchRelocator> RelocatedSession<'a, M, A> {
    /// Complete the session-wide cache and protection boundary.
    ///
    /// Every logical seal plan, backend protection plan and executable range
    /// is prepared before the first cache/protection mutation. Publication is
    /// available only on the returned [`SealedSession`].
    pub(crate) fn seal(
        mut self,
        cache: &mut ArchitectureCodeCache,
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
                            .contains(crate::memory::MemoryPermissions::EXECUTE)
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
        for image in &self.state.images {
            let runtime = &image.state;
            let allocation = image.allocation.allocation();
            let seal_plan = SealPlan::build(
                &allocation,
                runtime.load_bias(),
                self.profile.class(),
                runtime.load_segments(),
                runtime.regions(),
                runtime.relro(),
                runtime.stack(),
                runtime.metadata().relocations(),
            )
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
            let prepared = PreparedProtectionPlan::prepare_for_allocation(
                &*self.rollback.memory,
                &allocation,
                &seal_plan,
            )
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;

            for (segment, region) in runtime.load_segments().iter().zip(runtime.regions().iter()) {
                if segment
                    .permissions()
                    .contains(crate::memory::MemoryPermissions::EXECUTE)
                    && !region.runtime_range().is_empty()
                {
                    executable_ranges.push(region.runtime_range());
                }
            }
            prepared_seals.push(prepared);
        }

        let requirements = cache.requirements();
        let prepared_cache = cache
            .prepare(&executable_ranges)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        requirements
            .validate_prepared(&executable_ranges, &prepared_cache)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        cache
            .synchronize(prepared_cache)
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        for (image, prepared) in self.state.images.iter().zip(prepared_seals.into_iter()) {
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
        }

        let RelocatedState {
            images,
            imported,
            bindings,
        } = self.state;
        Ok(LinkSession {
            rollback: self.rollback,
            graph: self.graph,
            limits: self.limits,
            usage: self.usage,
            profile: self.profile,
            arch: self.arch,
            state: SealedSessionState {
                images,
                imported,
                bindings,
            },
        })
    }
}

impl<M: ImageMemory + ?Sized, A: ArchRelocator> SealedSession<'_, M, A> {
    /// Build the dependency-first init and reverse fini plans.
    ///
    /// Reads the post-relocation init/fini array words back through the
    /// session memory backend and validates each non-sentinel function target
    /// against its owner's executable region (and Thumb bit on ARM). The plans
    /// only *name* targets — nothing here calls a constructor.
    pub(crate) fn build_lifecycle_plans(&self) -> LoadResult<LifecyclePlans> {
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
    /// publication.
    ///
    /// Emits one [`LinkMapEntry`] per relocated image in image-id order and
    /// uses the root's runtime entry computed during mapping. The
    /// result holds no lease: it is the pure description the host publisher
    /// validates in `prepare_batch` before the committed snapshot is swapped.
    pub(crate) fn prepare_link_manifest(&self) -> LoadResult<PreparedLinkManifest> {
        let total = self.state.images.len() + self.state.imported.len();
        // Image-id indexed: the root and every loaded image contribute a
        // `Loaded` entry, and every imported Ready image a `Imported` entry at
        // its graph-assigned id, so the link map stays in stable id order even
        // when discovery interleaves loads and imports.
        let mut slots: Vec<Option<LinkMapImage>> = Vec::new();
        slots
            .try_reserve_exact(total)
            .map_err(|_| link_seal_oom())?;
        slots.resize_with(total, || None);
        for image in &self.state.images {
            slots[image.image_id.get() as usize] = Some(LinkMapImage::loaded(
                image.image_id,
                image.state.load_bias(),
                image.state.runtime_entry(),
            ));
        }
        for imported in &self.state.imported {
            slots[imported.image_id.get() as usize] = Some(LinkMapImage::imported(
                imported.image_id,
                imported.descriptor().load_bias(),
            ));
        }
        let mut images = Vec::new();
        images
            .try_reserve_exact(total)
            .map_err(|_| link_seal_oom())?;
        for slot in slots {
            images.push(slot.ok_or_else(|| {
                LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
                    .at_stage(LoadStage::LinkSeal)
            })?);
        }
        publish::build_manifest(&self.graph, &images)
    }

    /// Atomically publish the link product.
    ///
    /// Builds the lifecycle plans and the prepared manifest, lets the publisher
    /// complete every fallible check without mutating the visible snapshot,
    /// then moves the unique allocation leases out of the session rollback log
    /// into the publisher's committed owner in one infallible commit. On any
    /// `prepare_batch` failure the session drops and aborts every absorbed
    /// allocation; after a successful commit the rollback log is empty and the
    /// publisher's `Receipt` is the long-term owner of the committed images.
    pub(crate) fn publish<P: LinkPublisher>(
        self,
        publisher: &mut P,
    ) -> LoadResult<LinkProduct<P::Receipt>> {
        let plans = self.build_lifecycle_plans()?;
        let manifest = self.prepare_link_manifest()?;

        // One committed image per id: link-map facts plus the backing
        // allocation, in image-id order. Imported Ready images join the
        // committed context at their graph-assigned ids so their retained
        // export surface stays resolvable after publication; they
        // contribute no lease here — their unique lease lives in the registry.
        let total = self.state.images.len() + self.state.imported.len();
        // Drain the unique leases in creation order (== image-id order of the
        // loaded images only).
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(self.rollback.log.len())
            .map_err(|_| publish_oom())?;

        let LinkSession {
            mut rollback,
            graph,
            limits,
            usage,
            profile,
            arch: _,
            state,
        } = self;
        let SealedSessionState {
            images,
            imported,
            bindings,
        } = state;

        let mut slots: Vec<Option<CommittedImage>> = Vec::new();
        slots.try_reserve_exact(total).map_err(|_| publish_oom())?;
        slots.resize_with(total, || None);

        let mut snapshot_bytes = 0u64;
        for image in images {
            let node = graph.node(image.image_id).ok_or_else(publish_invalid)?;
            let needed = image.state.metadata().needed();
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(needed.len())
                .map_err(|_| publish_oom())?;
            for (index, name) in needed.iter().enumerate() {
                let edge = graph
                    .edges()
                    .iter()
                    .find(|edge| {
                        edge.requester() == image.image_id && edge.needed_index() as usize == index
                    })
                    .ok_or_else(publish_invalid)?;
                let provider = graph.node(edge.provider()).ok_or_else(publish_invalid)?;
                dependencies.push(ImageDependency::new(
                    name.try_clone()?,
                    provider.artifact().try_clone()?,
                    matches!(
                        provider.ownership(),
                        ImageOwnership::SystemCandidate | ImageOwnership::ExternalReady
                    ),
                ));
            }
            let snapshot = PublishedLoadSnapshot::new(profile, image.role, dependencies);
            snapshot_bytes = snapshot_bytes
                .checked_add(snapshot.metadata_bytes())
                .ok_or_else(session_overflow)?;
            let (regions, load_segments, load_bias, program_headers, symbols) =
                image.state.into_publish_parts();
            let ownership = node.ownership();
            let descriptor = Arc::new(
                PublishedImageDescriptor::from_node_and_state(
                    node,
                    regions,
                    load_segments,
                    load_bias,
                    program_headers,
                    symbols,
                    snapshot,
                )
                .map_err(|error| error.at_stage(LoadStage::Publish))?,
            );
            slots[image.image_id.get() as usize] =
                Some(CommittedImage::new(image.image_id, ownership, descriptor));
        }
        for imported in imported {
            let image_id = imported.image_id;
            slots[image_id.get() as usize] = Some(CommittedImage::new(
                image_id,
                graph.node(image_id).ok_or_else(publish_oom)?.ownership(),
                imported.descriptor,
            ));
        }

        let mut committed = Vec::new();
        committed
            .try_reserve_exact(total)
            .map_err(|_| publish_oom())?;
        for slot in slots {
            committed.push(slot.ok_or_else(|| {
                LoadError::new(LoadErrorKind::BadElf, ErrorContext::None)
                    .at_stage(LoadStage::Publish)
            })?);
        }

        let context = LinkContext::new(graph, committed);
        let extra_metadata = publisher
            .prepare_metadata(&context, &plans, &bindings)
            .map_err(|error| error.at_stage(LoadStage::Publish))?;
        let metadata_bytes = usage
            .runtime_metadata_bytes
            .checked_add(extra_metadata)
            .and_then(|bytes| bytes.checked_add(snapshot_bytes))
            .ok_or_else(session_overflow)?;
        limits.check_total_runtime_metadata_bytes(metadata_bytes)?;
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
            context, entry, plans, link_map, bindings, receipt,
        ))
    }
}

fn session_error(kind: LoadErrorKind, context: ErrorContext) -> LoadError {
    LoadError::new(kind, context)
}

fn session_overflow() -> LoadError {
    session_error(LoadErrorKind::IntegerOverflow, ErrorContext::None)
}

/// Snapshot every relocation's scope decision: the
/// requester, the referenced symbol name and the winning provider — into the
/// published bindings. Symbol-less (`R_ARM_RELATIVE`) relocations record an
/// empty name and no provider; an undefined weak records its name with no
/// provider (it bound to zero). The name copies are charged against the
/// runtime metadata budget.
fn record_bindings(
    operations: &[relocate::SessionRelocation],
    symbols: &[&SymbolTable],
    limits: &SessionLimits,
    usage: &mut SessionUsage,
) -> LoadResult<Vec<RelocationBinding>> {
    /// The byte name of `index` in `owner`'s symbol table, empty when absent.
    fn symbol_name<'t>(symbols: &[&'t SymbolTable], owner: ImageId, index: u32) -> &'t [u8] {
        let Some(table) = symbols.get(owner.get() as usize) else {
            return &[];
        };
        let Some(entry) = table.entry(index) else {
            return &[];
        };
        table.name(entry)
    }

    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(operations.len())
        .map_err(|_| link_relocation_oom())?;
    for operation in operations {
        let record = operation.record();
        let (name, provider) = match operation.source() {
            RelocationSource::Relative => (alloc::vec![], None),
            RelocationSource::UndefinedWeak => (
                symbol_name(symbols, operation.owner(), record.symbol_index()).to_vec(),
                None,
            ),
            RelocationSource::Symbol(resolved) => (
                symbol_name(symbols, operation.owner(), record.symbol_index()).to_vec(),
                Some(resolved.owner()),
            ),
        };
        // Fixed overhead per binding plus the copied name bytes.
        let bytes = (core::mem::size_of::<RelocationBinding>() as u64)
            .checked_add(name.len() as u64)
            .ok_or_else(session_overflow)?;
        usage.record_relocation_bindings(bytes, limits)?;
        bindings.push(RelocationBinding::new(operation.owner(), name, provider));
    }
    Ok(bindings)
}

fn publish_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::Publish)
}

fn publish_invalid() -> LoadError {
    LoadError::new(LoadErrorKind::BadElf, ErrorContext::None).at_stage(LoadStage::Publish)
}

fn link_seal_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::LinkSeal)
}

fn link_relocation_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None).at_stage(LoadStage::LinkRelocate)
}
