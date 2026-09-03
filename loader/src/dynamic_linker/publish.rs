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

//! Link map and prepared manifest for atomic publication (S9, §13).
//!
//! [`build_manifest`] derives the per-image [`LinkMapEntry`] list and the
//! root's runtime entry from the closed dependency graph and the relocated
//! images. The result is the [`PreparedLinkManifest`] the host
//! [`LinkPublisher`](crate::dynamic_linker::LinkPublisher) validates in C17-b's
//! `prepare_batch` — a pure, allocation-only description that never turns a
//! target address into a host function pointer and never touches the committed
//! snapshot. The owned [`LinkContext`]/[`crate::dynamic_linker::CommittedImage`]
//! and the [`crate::dynamic_linker::LinkProduct`] land with C17-b, where the
//! session's graph/scopes/images move into the committed owner.

use alloc::vec::Vec;

use crate::{
    address::{TargetAddress, TargetRange},
    dynamic_linker::{
        graph::DependencyGraph, ArtifactIdentity, DependencyName, FiniPlan, ImageId,
        ImageOwnership, InitPlan, LoadMetrics, PublishedImageDescriptor, ScopeSet,
    },
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    image::{LoadedRegion, SealedState},
    memory::{AllocationLease, ImageAllocation},
};

/// One entry of the published link map, in stable image-id order (§13.2).
///
/// The fields are chosen to support crash/audit introspection (`dl_iterate_phdr`-
/// style) and the publisher's identity/generation/capacity checks without
/// owning a lease: the owner, the artifact identity (which carries the build id
/// and generation), the SONAME, the load bias, the runtime entry (root only),
/// and the mapped runtime span. A later [`crate::dynamic_linker::CommittedImage`]
/// adds the long-lived allocation lease that outlives publication.
#[derive(Clone, Debug)]
pub struct LinkMapEntry {
    owner: ImageId,
    identity: ArtifactIdentity,
    soname: Option<DependencyName>,
    ownership: ImageOwnership,
    load_bias: TargetAddress,
    entry: Option<TargetAddress>,
    map_span: TargetRange,
}

impl LinkMapEntry {
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        owner: ImageId,
        identity: ArtifactIdentity,
        soname: Option<DependencyName>,
        ownership: ImageOwnership,
        load_bias: TargetAddress,
        entry: Option<TargetAddress>,
        map_span: TargetRange,
    ) -> Self {
        Self {
            owner,
            identity,
            soname,
            ownership,
            load_bias,
            entry,
            map_span,
        }
    }

    #[inline]
    pub const fn owner(&self) -> ImageId {
        self.owner
    }

    #[inline]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    #[inline]
    pub const fn soname(&self) -> Option<&DependencyName> {
        self.soname.as_ref()
    }

    /// How this image participates in the link (§12.1): a session-private
    /// artifact, a system candidate, or an externally imported Ready DSO. The
    /// publisher uses it — never the image id or SONAME — to decide which lease
    /// owner receives the image's allocation.
    #[inline]
    pub const fn ownership(&self) -> ImageOwnership {
        self.ownership
    }

    #[inline]
    pub const fn load_bias(&self) -> TargetAddress {
        self.load_bias
    }

    /// The runtime entry, present only for the executable root (§2.3).
    #[inline]
    pub const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    #[inline]
    pub const fn map_span(&self) -> TargetRange {
        self.map_span
    }
}

/// The pre-commit publication description a [`LinkPublisher`](crate::dynamic_linker::LinkPublisher)
/// validates (§13.1). It owns only the allocatable facts the publisher must
/// check (entry, link-map slots); it holds no lease and mutates no snapshot.
#[derive(Clone, Debug)]
pub struct PreparedLinkManifest {
    entry: TargetAddress,
    link_map: Vec<LinkMapEntry>,
}

impl PreparedLinkManifest {
    /// The root's mapped runtime entry, Thumb bit preserved.
    #[inline]
    pub const fn entry(&self) -> TargetAddress {
        self.entry
    }

    #[inline]
    pub fn link_map(&self) -> &[LinkMapEntry] {
        &self.link_map
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (TargetAddress, Vec<LinkMapEntry>) {
        (self.entry, self.link_map)
    }
}

/// Per-image inputs to manifest construction, borrowed from the session's
/// relocated images.
pub(crate) struct LinkMapImage<'a> {
    image_id: ImageId,
    load_bias: TargetAddress,
    runtime_entry: TargetAddress,
    regions: &'a [LoadedRegion],
}

impl<'a> LinkMapImage<'a> {
    #[inline]
    pub(crate) const fn new(
        image_id: ImageId,
        load_bias: TargetAddress,
        runtime_entry: TargetAddress,
        regions: &'a [LoadedRegion],
    ) -> Self {
        Self {
            image_id,
            load_bias,
            runtime_entry,
            regions,
        }
    }
}

/// Build the prepared manifest from the closed graph and relocated images.
///
/// The link map is emitted in image-id order (root first, then discovery
/// order). Only the root contributes a runtime entry (§2.3); every entry keeps
/// its owner and identity so a publisher can validate capacity, identity and
/// generation without dereferencing a bare address.
pub(crate) fn build_manifest(
    graph: &DependencyGraph,
    images: &[LinkMapImage<'_>],
) -> LoadResult<PreparedLinkManifest> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(images.len())
        .map_err(|_| publish_oom())?;

    let mut root_entry = None;
    for image in images {
        let node = graph
            .node(image.image_id)
            .ok_or_else(|| publish_error(LoadErrorKind::BadElf, ErrorContext::None))?;

        let entry = if image.image_id.get() == 0 {
            let runtime = image.runtime_entry;
            root_entry = Some(runtime);
            Some(runtime)
        } else {
            None
        };

        entries.push(LinkMapEntry {
            owner: image.image_id,
            identity: node.artifact().try_clone()?,
            soname: node.soname().map(DependencyName::try_clone).transpose()?,
            ownership: node.ownership(),
            load_bias: image.load_bias,
            entry,
            map_span: image_span(image.regions)?,
        });
    }

    let entry =
        root_entry.ok_or_else(|| publish_error(LoadErrorKind::BadElf, ErrorContext::None))?;
    Ok(PreparedLinkManifest {
        entry,
        link_map: entries,
    })
}

/// The mapped runtime span of an image: the union of its load regions' runtime
/// ranges. Every mapped image has at least one region (S3 rejects zero), so an
/// empty region set fails closed rather than fabricating a zero-length span.
fn image_span(regions: &[LoadedRegion]) -> LoadResult<TargetRange> {
    let mut start = None;
    let mut end = None;
    for region in regions {
        let range = region.runtime_range();
        let range_end = range
            .end()
            .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
        start = Some(match start {
            Some(current) => core::cmp::min(current, range.start()),
            None => range.start(),
        });
        end = Some(match end {
            Some(current) => core::cmp::max(current, range_end),
            None => range_end,
        });
    }
    match (start, end) {
        (Some(start), Some(end)) => {
            let len = end
                .checked_sub(start)
                .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
            Ok(TargetRange::new(start, len))
        }
        _ => Err(publish_error(
            LoadErrorKind::IncorrectLayout,
            ErrorContext::None,
        )),
    }
}

fn publish_error(kind: LoadErrorKind, context: ErrorContext) -> LoadError {
    LoadError::new(kind, context).at_stage(LoadStage::LinkSeal)
}

fn publish_oom() -> LoadError {
    publish_error(LoadErrorKind::OutOfMemory, ErrorContext::None)
}

/// One image in a published link context (§13.2).
///
/// Unlike [`LinkMapEntry`], this value pairs the link-map facts with the
/// full [`PublishedImageDescriptor`]: the immutable export surface, published
/// regions, program-header summary, allocation descriptor and sealed state a
/// later link imports instead of re-loading (C23-a). It holds no lease: the
/// unique allocation lease is transferred into the publisher's `Receipt` at
/// commit, which is the long-term owner (§13.2 "CommittedImage 或 publisher
/// receipt 必须长期持有 allocation lease").
#[derive(Debug)]
pub struct CommittedImage {
    owner: ImageId,
    descriptor: PublishedImageDescriptor,
}

impl CommittedImage {
    #[inline]
    pub(crate) fn new(owner: ImageId, descriptor: PublishedImageDescriptor) -> Self {
        Self { owner, descriptor }
    }

    #[inline]
    pub const fn owner(&self) -> ImageId {
        self.owner
    }

    /// The immutable descriptor the registry retains for cross-application
    /// import (C23-a). It is also the source of the allocation and sealed state
    /// this image occupies.
    #[inline]
    pub const fn descriptor(&self) -> &PublishedImageDescriptor {
        &self.descriptor
    }

    #[inline]
    pub const fn allocation(&self) -> ImageAllocation {
        self.descriptor.allocation()
    }

    #[inline]
    pub(crate) const fn sealed(&self) -> &SealedState {
        self.descriptor.sealed()
    }
}

/// The owned, immutable context a [`LinkProduct`] exposes (§13.2): the closed
/// dependency graph, the frozen scopes, and one committed image per id.
pub struct LinkContext {
    graph: DependencyGraph,
    scopes: ScopeSet,
    images: Vec<CommittedImage>,
}

impl LinkContext {
    #[inline]
    pub(crate) fn new(
        graph: DependencyGraph,
        scopes: ScopeSet,
        images: Vec<CommittedImage>,
    ) -> Self {
        Self {
            graph,
            scopes,
            images,
        }
    }

    #[inline]
    pub(crate) const fn graph(&self) -> &DependencyGraph {
        &self.graph
    }

    #[inline]
    pub(crate) const fn scopes(&self) -> &ScopeSet {
        &self.scopes
    }

    #[inline]
    pub fn images(&self) -> &[CommittedImage] {
        &self.images
    }
}

/// The lease payload handed to [`LinkPublisher::commit_batch`](LinkPublisher::commit_batch).
///
/// Every fallible check (capacity, identity, generation, entry, link-map slot)
/// already happened in `prepare_batch`; the publisher's prepared state encodes
/// the entry and link-map slots. The only thing the infallible commit step
/// must move is the set of unique allocation leases, so this value is exactly
/// that set, in image-id order.
pub struct CommittingLinkProduct {
    leases: Vec<AllocationLease>,
}

impl CommittingLinkProduct {
    #[inline]
    pub(crate) fn new(leases: Vec<AllocationLease>) -> Self {
        Self { leases }
    }

    #[inline]
    pub fn into_leases(self) -> Vec<AllocationLease> {
        self.leases
    }
}

/// The atomic publication boundary between the loader and the external system
/// (S9, §13.1).
///
/// `prepare_batch` performs every fallible check without mutating the visible
/// snapshot; `commit_batch` only moves the prepared state and the leases, and
/// must not allocate, validate, panic, or otherwise fail. The returned
/// `Receipt` is the publisher's long-term owner of the committed images.
pub trait LinkPublisher {
    type PreparedBatch;
    type Receipt;

    fn prepare_batch(&mut self, manifest: &PreparedLinkManifest)
        -> LoadResult<Self::PreparedBatch>;

    /// # Safety
    ///
    /// `prepared` and `product` must come from the same active link session on
    /// this publisher. Implementations must move the leases into the committed
    /// owner and must not allocate, validate, panic, or otherwise fail.
    unsafe fn commit_batch(
        &mut self,
        prepared: Self::PreparedBatch,
        product: CommittingLinkProduct,
    ) -> Self::Receipt;
}

/// The published result of a link session (§13.2).
///
/// This is the immutable snapshot a reader observes after commit: the owned
/// context, the root entry, the constructor/destructor plans, the flat link
/// map, the session metrics, and the publisher's receipt (the long-term owner
/// of every committed allocation lease).
pub struct LinkProduct<Receipt> {
    context: LinkContext,
    entry: TargetAddress,
    init_plan: InitPlan,
    fini_plan: FiniPlan,
    link_map: Vec<LinkMapEntry>,
    metrics: LoadMetrics,
    publication: Receipt,
}

impl<Receipt> LinkProduct<Receipt> {
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        context: LinkContext,
        entry: TargetAddress,
        init_plan: InitPlan,
        fini_plan: FiniPlan,
        link_map: Vec<LinkMapEntry>,
        metrics: LoadMetrics,
        publication: Receipt,
    ) -> Self {
        Self {
            context,
            entry,
            init_plan,
            fini_plan,
            link_map,
            metrics,
            publication,
        }
    }

    #[inline]
    pub const fn context(&self) -> &LinkContext {
        &self.context
    }

    /// The root's runtime entry (Thumb bit preserved on ARM).
    #[inline]
    pub const fn entry(&self) -> TargetAddress {
        self.entry
    }

    #[inline]
    pub const fn init_plan(&self) -> &InitPlan {
        &self.init_plan
    }

    #[inline]
    pub const fn fini_plan(&self) -> &FiniPlan {
        &self.fini_plan
    }

    #[inline]
    pub fn link_map(&self) -> &[LinkMapEntry] {
        &self.link_map
    }

    #[inline]
    pub fn metrics(&self) -> LoadMetrics {
        self.metrics
    }

    #[inline]
    pub const fn publication(&self) -> &Receipt {
        &self.publication
    }
}
