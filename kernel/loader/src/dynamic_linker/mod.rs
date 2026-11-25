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

//! ELF dependency discovery, eager relocation and finalization.
//!
//! `discover` validates the dependency graph and retains its readers. `link`
//! maps and relocates its images. `seal` orders callbacks, synchronizes code
//! and applies final protections before returning the owning results.

mod discover;
mod link;
mod seal;

mod exports;
mod lifecycle;
mod scope;
pub(crate) mod symbol;

use self::{discover::discover_with_existing, link::link_in_scope, scope::LinkScope};
use alloc::vec::Vec;

use crate::{
    error::{ErrorContext, LoadErrorKind, LoadStage},
    load::SealedBatch,
    profile::LoadPurpose,
    CodeCache, ImageAllocator, LoadAndLinkRequest, LoadError, LoadResult, LoadedImages,
};

pub use discover::{discover, DependencyEdge, DependencyImage, DependencyPlan, DependencyResolver};
pub use exports::ExportedSymbols;
pub use lifecycle::LinkedLifecycle;
pub use link::link;
pub(crate) use scope::lookup_symbol;
pub use seal::{LinkedImage, LinkedImages};

/// Discover, link and seal additions to an already loaded application graph.
pub(crate) fn prepare_plugin<D, M, C>(
    group: &LoadedImages<D::Key, M::Allocation>,
    root: D::Key,
    request: LoadAndLinkRequest,
    resolver: &mut D,
    allocator: M,
    cache: &mut C,
) -> LoadResult<SealedBatch<D::Key, M::Allocation>>
where
    D: DependencyResolver,
    M: ImageAllocator,
    C: CodeCache + ?Sized,
{
    let (request, dependency_limits, limits) = request.into_parts();
    discover_with_existing(
        root,
        request.with_purpose(LoadPurpose::SharedObject),
        dependency_limits,
        resolver,
        group.images().len(),
        group.edges().len(),
        |key| group.find(key),
    )
    .and_then(|plan| {
        let scope =
            LinkScope::for_plugin(group, plan.images().len(), plan.edges(), &dependency_limits)
                .map_err(|error| error.at_stage(LoadStage::Discover))?;
        link_in_scope(plan, limits, allocator, scope)
    })
    .and_then(|linked| linked.seal_batch(cache))
}

fn reserve<T>(capacity: usize) -> LoadResult<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
    Ok(values)
}
