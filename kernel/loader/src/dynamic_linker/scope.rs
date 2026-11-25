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

//! Build a plugin's symbol scope from its application startup and dependency graph.

use alloc::vec::Vec;

use super::{reserve, DependencyEdge};
use crate::{
    error::{ErrorContext, ExistingImageReason, LoadErrorKind},
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
        let mut order = reserve(count)?;
        let mut visited = reserve(count)?;
        visited.resize(count, false);
        visited[first] = true;
        order.push(first);
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
            let edges = if image < first {
                group.edges()
            } else {
                new_edges
            };
            let start = edges.partition_point(|edge| edge.requester() < image);
            for edge in &edges[start..] {
                if edge.requester() != image {
                    break;
                }
                let provider = edge.provider();
                if !visited[provider] {
                    limits.check_depth(depth + 1)?;
                    visited[provider] = true;
                    order.push(provider);
                }
            }
        }

        // The startup prefix already contains these images in startup order.
        order.retain(|&index| index >= group.startup_count());
        let scope = Self {
            group: Some(group),
            plugin_order: order,
        };
        for index in scope.indexes(new_count).filter(|&index| index < first) {
            let image = &group.images()[index];
            if image.exports().is_none() {
                return Err(LoadError::new(
                    LoadErrorKind::IncorrectLayout,
                    ErrorContext::ExistingImage {
                        index,
                        base: image.image().allocation().base(),
                        reason: ExistingImageReason::MissingExportIndex,
                    },
                ));
            }
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
