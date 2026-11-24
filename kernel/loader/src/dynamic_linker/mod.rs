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

//! ELF dependency discovery, eager relocation and lifecycle ordering.

mod dependency;
mod exports;
mod lifecycle;
mod link;
pub(crate) mod symbol;

use alloc::vec::Vec;

use crate::{
    error::{ErrorContext, LoadErrorKind},
    LoadError, LoadResult,
};

pub use dependency::{
    discover, DependencyEdge, DependencyImage, DependencyPlan, DependencyResolver,
};
pub use exports::ExportedSymbols;
pub use lifecycle::LinkedLifecycle;
pub use link::{link, LinkedImage, LinkedImages};

fn reserve<T>(capacity: usize) -> LoadResult<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
    Ok(values)
}
