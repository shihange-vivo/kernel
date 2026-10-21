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

//! Source, lookup, mapped-instance and execution-domain identities.

use crate::{
    error::{ErrorContext, LoadErrorKind},
    LoadError, LoadResult,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ExecutionDomainId(u64);
impl ExecutionDomainId {
    pub const FLAT: Self = Self(1);
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
fn fresh() -> LoadResult<u64> {
    NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map(|id| id as u64)
        .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))
}

/// Identity of one immutable opened input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactId(u64);
impl ArtifactId {
    pub fn fresh() -> LoadResult<Self> {
        fresh().map(Self)
    }
}

/// Identity of one mapping, distinct after unload/reload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImageInstanceId(u64);
impl ImageInstanceId {
    pub fn fresh() -> LoadResult<Self> {
        fresh().map(Self)
    }
}

/// Host-defined namespace key, independent of the opened bytes or SONAME.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImageKey {
    scope: u64,
    identity: Arc<Vec<u8>>,
}
impl ImageKey {
    pub fn new(scope: u64, identity: &[u8]) -> LoadResult<Self> {
        if identity.is_empty() || identity.contains(&0) {
            return Err(LoadError::new(LoadErrorKind::Backend, ErrorContext::None));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(identity.len())
            .map_err(|_| crate::error::oom())?;
        bytes.extend_from_slice(identity);
        Ok(Self {
            scope,
            identity: Arc::new(bytes),
        })
    }
    pub const fn scope(&self) -> u64 {
        self.scope
    }
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
}
