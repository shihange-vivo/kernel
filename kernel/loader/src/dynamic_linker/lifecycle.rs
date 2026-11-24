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

//! Order the lifecycle of already relocated images.

use alloc::vec::Vec;

use super::{reserve, DependencyEdge};
use crate::{memory::TargetAddress, LifecyclePlan, LoadResult};

/// Callbacks for one linked dependency graph. Keep the linked images alive
/// while using these target addresses. The host can invoke the callbacks after
/// the mappings are finalized.
#[derive(Debug)]
pub struct LinkedLifecycle {
    plans: Vec<LifecyclePlan>,
    order: Vec<usize>,
}

impl LinkedLifecycle {
    pub(super) fn build(edges: &[DependencyEdge], plans: Vec<LifecyclePlan>) -> LoadResult<Self> {
        let order = dependency_order(plans.len(), edges)?;
        Ok(Self { plans, order })
    }

    /// The root's preinitializers, for execution before any image initialization.
    pub fn preinit(&self) -> &[TargetAddress] {
        self.plans[0].preinit()
    }

    /// Provider images initialize ahead of their requesters. Within a cycle,
    /// images initialize in discovery order.
    pub fn init(&self) -> impl Iterator<Item = TargetAddress> + '_ {
        self.order
            .iter()
            .flat_map(|&index| self.plans[index].init().iter().copied())
    }

    /// Visit images in reverse initialization order, preserving each image's
    /// own finalizer order.
    pub fn fini(&self) -> impl Iterator<Item = TargetAddress> + '_ {
        self.order
            .iter()
            .rev()
            .flat_map(|&index| self.plans[index].fini().iter().copied())
    }
}

#[derive(Clone, Copy, Default)]
struct Visit {
    index: Option<usize>,
    low_link: usize,
    active: bool,
}

/// Iterative Tarjan traversal from the root. Edges point from requesters to
/// providers, so components finish in dependency-first order. Sorting each
/// component gives a stable discovery order for members of a dependency cycle.
fn dependency_order(image_count: usize, edges: &[DependencyEdge]) -> LoadResult<Vec<usize>> {
    let mut visits = reserve(image_count)?;
    visits.resize(image_count, Visit::default());
    let mut active = reserve(image_count)?;
    let mut traversal = reserve(image_count)?;
    let mut order = reserve(image_count)?;
    let mut next_index = 0;

    // Discovery guarantees that every image is reachable from the root and
    // that edges are grouped by requester in image order.
    traversal.push((0, 0));
    while let Some((image, next_edge)) = traversal.last_mut() {
        let image = *image;
        if visits[image].index.is_none() {
            visits[image] = Visit {
                index: Some(next_index),
                low_link: next_index,
                active: true,
            };
            next_index += 1;
            active.push(image);
        }

        if let Some(edge) = edges
            .get(*next_edge)
            .filter(|edge| edge.requester() == image)
        {
            *next_edge += 1;
            let provider = edge.provider();
            match visits[provider] {
                Visit { index: None, .. } => {
                    let first_edge = edges.partition_point(|edge| edge.requester() < provider);
                    traversal.push((provider, first_edge));
                }
                Visit {
                    index: Some(index),
                    active: true,
                    ..
                } => visits[image].low_link = visits[image].low_link.min(index),
                _ => (),
            }
            continue;
        }

        let low_link = visits[image].low_link;
        if visits[image].index == Some(low_link) {
            let start = order.len();
            while let Some(member) = active.pop() {
                visits[member].active = false;
                order.push(member);
                if member == image {
                    break;
                }
            }
            order[start..].sort_unstable();
        }

        traversal.pop();
        if let Some(&(requester, _)) = traversal.last() {
            visits[requester].low_link = visits[requester].low_link.min(low_link);
        }
    }
    Ok(order)
}
