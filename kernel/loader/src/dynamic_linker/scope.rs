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

//! Build symbol search orders from startup images and dependency edges.

use alloc::vec::Vec;

use super::{reserve, symbol::find_in_scope, DependencyEdge, ExportedSymbols};
use crate::{
    error::{ErrorContext, ExistingImageReason, LoadErrorKind},
    memory::TargetAddress,
    profile::DependencyLimits,
    ImageMapping, LoadError, LoadResult, LoadedImages, LoadedObject,
};

pub(super) struct LinkScope<'a, K, A: ImageMapping> {
    group: Option<&'a LoadedImages<K, A>>,
    plugin_order: Vec<usize>,
}

impl<'a, K: Eq, A: ImageMapping> LinkScope<'a, K, A> {
    pub(super) const fn standalone() -> Self {
        Self {
            group: None,
            plugin_order: Vec::new(),
        }
    }

    pub(super) fn for_plugin(
        group: &'a LoadedImages<K, A>,
        new_count: usize,
        new_edges: &[DependencyEdge],
        limits: &DependencyLimits,
    ) -> LoadResult<Self> {
        let first = group.images().len();
        let count = first + new_count;
        let mut order = dependency_scope(
            first,
            count,
            |image| {
                if image < first {
                    group.edges()
                } else {
                    new_edges
                }
            },
            Some(limits),
        )?;

        // The startup prefix already contains these images in startup order.
        order.retain(|&index| index >= group.startup_count());
        let scope = Self {
            group: Some(group),
            plugin_order: order,
        };
        for index in scope.indexes(new_count).filter(|&index| index < first) {
            exports_at(group.images(), index)?;
        }
        Ok(scope)
    }

    pub(super) fn existing(&self) -> &'a [LoadedObject<K, A>] {
        self.group.map_or(&[], LoadedImages::images)
    }

    pub(super) fn indexes(&self, new_count: usize) -> impl Iterator<Item = usize> + '_ {
        let prefix_len = self.group.map_or(new_count, LoadedImages::startup_count);
        (0..prefix_len).chain(self.plugin_order.iter().copied())
    }
}

pub(crate) fn lookup_symbol<K: Eq, A: ImageMapping>(
    group: &LoadedImages<K, A>,
    root: usize,
    name: &[u8],
) -> LoadResult<Option<TargetAddress>> {
    let images = group.images();
    if root >= images.len() {
        return Err(LoadError::new(
            LoadErrorKind::OutOfBounds,
            ErrorContext::ImageIndex {
                index: root,
                count: images.len(),
            },
        ));
    }
    if let Some(address) = exports_at(images, root)?.find(name) {
        return Ok(Some(address));
    }
    let order = dependency_scope(root, images.len(), |_| group.edges(), None)?;
    let found = find_in_scope(order.into_iter().skip(1), |index| {
        Ok(exports_at(images, index)?.find(name))
    })?;
    Ok(found.map(|(_, address)| address))
}

pub(super) fn exports_at<K, A: ImageMapping>(
    images: &[LoadedObject<K, A>],
    index: usize,
) -> LoadResult<&ExportedSymbols> {
    let image = &images[index];
    image.exports().ok_or_else(|| {
        LoadError::new(
            LoadErrorKind::IncorrectLayout,
            ErrorContext::ExistingImage {
                index,
                base: image.image().allocation().base(),
                reason: ExistingImageReason::MissingExportIndex,
            },
        )
    })
}

fn dependency_scope<'a>(
    root: usize,
    count: usize,
    edges_for: impl Fn(usize) -> &'a [DependencyEdge],
    limits: Option<&DependencyLimits>,
) -> LoadResult<Vec<usize>> {
    let mut order = reserve(count)?;
    let mut visited = reserve(count)?;
    visited.resize(count, false);
    visited[root] = true;
    order.push(root);
    let mut depth = 0;
    let mut level_end = order.len();
    let mut next = 0;
    while next < order.len() {
        if next == level_end {
            depth += 1;
            level_end = order.len();
        }
        let image = order[next];
        next += 1;
        let edges = edges_for(image);
        let start = edges.partition_point(|edge| edge.requester() < image);
        for edge in &edges[start..] {
            if edge.requester() != image {
                break;
            }
            let provider = edge.provider();
            if !visited[provider] {
                if let Some(limits) = limits {
                    limits.check_depth(depth + 1)?;
                }
                visited[provider] = true;
                order.push(provider);
            }
        }
    }
    Ok(order)
}
