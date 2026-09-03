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

use alloc::{boxed::Box, vec::Vec};

use crate::{
    address::{TargetAddress, TargetRange},
    dynamic_linker::{graph::DependencyGraph, ArtifactIdentity, DependencyName, ImageId},
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    image::LoadedRegion,
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
pub(crate) struct LinkMapEntry {
    owner: ImageId,
    identity: ArtifactIdentity,
    soname: Option<DependencyName>,
    load_bias: TargetAddress,
    entry: Option<TargetAddress>,
    map_span: TargetRange,
}

impl LinkMapEntry {
    #[inline]
    pub(crate) const fn owner(&self) -> ImageId {
        self.owner
    }

    #[inline]
    pub(crate) const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    #[inline]
    pub(crate) const fn soname(&self) -> Option<&DependencyName> {
        self.soname.as_ref()
    }

    #[inline]
    pub(crate) const fn load_bias(&self) -> TargetAddress {
        self.load_bias
    }

    /// The runtime entry, present only for the executable root (§2.3).
    #[inline]
    pub(crate) const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    #[inline]
    pub(crate) const fn map_span(&self) -> TargetRange {
        self.map_span
    }
}

/// The pre-commit publication description a [`LinkPublisher`](crate::dynamic_linker::LinkPublisher)
/// validates (§13.1). It owns only the allocatable facts the publisher must
/// check (entry, link-map slots); it holds no lease and mutates no snapshot.
#[derive(Clone, Debug)]
pub(crate) struct PreparedLinkManifest {
    entry: TargetAddress,
    link_map: Box<[LinkMapEntry]>,
}

impl PreparedLinkManifest {
    /// The root's runtime entry: `load_bias + entry_vaddr`, Thumb bit preserved.
    #[inline]
    pub(crate) const fn entry(&self) -> TargetAddress {
        self.entry
    }

    #[inline]
    pub(crate) fn link_map(&self) -> &[LinkMapEntry] {
        &self.link_map
    }
}

/// Per-image inputs to manifest construction, borrowed from the session's
/// relocated images.
pub(crate) struct LinkMapImage<'a> {
    image_id: ImageId,
    load_bias: TargetAddress,
    entry_vaddr: TargetAddress,
    regions: &'a [LoadedRegion],
}

impl<'a> LinkMapImage<'a> {
    #[inline]
    pub(crate) const fn new(
        image_id: ImageId,
        load_bias: TargetAddress,
        entry_vaddr: TargetAddress,
        regions: &'a [LoadedRegion],
    ) -> Self {
        Self {
            image_id,
            load_bias,
            entry_vaddr,
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
            let runtime = image
                .load_bias
                .checked_add(image.entry_vaddr.get())
                .map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
            root_entry = Some(runtime);
            Some(runtime)
        } else {
            None
        };

        entries.push(LinkMapEntry {
            owner: image.image_id,
            identity: node.artifact().clone(),
            soname: node.soname().cloned(),
            load_bias: image.load_bias,
            entry,
            map_span: image_span(image.regions)?,
        });
    }

    let entry = root_entry.ok_or_else(|| publish_error(LoadErrorKind::BadElf, ErrorContext::None))?;
    Ok(PreparedLinkManifest {
        entry,
        link_map: entries.into_boxed_slice(),
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
        let range_end = range.end().map_err(|error| error.at_stage(LoadStage::LinkSeal))?;
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
        _ => Err(publish_error(LoadErrorKind::IncorrectLayout, ErrorContext::None)),
    }
}

fn publish_error(kind: LoadErrorKind, context: ErrorContext) -> LoadError {
    LoadError::new(kind, context).at_stage(LoadStage::LinkSeal)
}

fn publish_oom() -> LoadError {
    publish_error(LoadErrorKind::OutOfMemory, ErrorContext::None)
}
