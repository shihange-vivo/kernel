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

//! Host-supplied instruction publication contracts; no native instructions.

use alloc::vec::Vec;

use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::address::{TargetAddress, TargetRange},
    LoadError, LoadResult,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionScope {
    CurrentExecutionContext,
    AllExecutionContexts,
}

impl ExecutionScope {
    pub fn covers(self, required: Self) -> bool {
        matches!(self, Self::AllExecutionContexts) || self == required
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMaintenance {
    CoherentInstructionCache,
    InstructionFence,
    BarrierOnly,
    CleanAndInvalidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheRequirements {
    scope: ExecutionScope,
}

impl CacheRequirements {
    pub const CURRENT_EXECUTION_CONTEXT: Self = Self::new(ExecutionScope::CurrentExecutionContext);

    pub const fn new(scope: ExecutionScope) -> Self {
        Self { scope }
    }

    pub const fn scope(self) -> ExecutionScope {
        self.scope
    }

    pub fn validate_prepared<P: CacheSync + ?Sized>(
        self,
        executable_ranges: &[TargetRange],
        prepared: &P,
    ) -> LoadResult<()> {
        if prepared.executable_ranges() != executable_ranges {
            return Err(cache_contract_error(executable_ranges));
        }
        if prepared.scope().covers(self.scope) {
            Ok(())
        } else {
            Err(cache_capability_error())
        }
    }
}

#[derive(Debug)]
pub struct PreparedCacheSync {
    executable_ranges: Vec<TargetRange>,
    scope: ExecutionScope,
    maintenance: CacheMaintenance,
}

impl PreparedCacheSync {
    pub fn try_new(
        executable_ranges: &[TargetRange],
        scope: ExecutionScope,
        maintenance: CacheMaintenance,
    ) -> LoadResult<Self> {
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(executable_ranges.len())
            .map_err(|_| cache_oom())?;
        for range in executable_ranges {
            range.end()?;
            ranges.push(*range);
        }
        Ok(Self {
            executable_ranges: ranges,
            scope,
            maintenance,
        })
    }

    pub fn executable_ranges(&self) -> &[TargetRange] {
        &self.executable_ranges
    }

    pub const fn scope(&self) -> ExecutionScope {
        self.scope
    }

    pub const fn maintenance(&self) -> CacheMaintenance {
        self.maintenance
    }
}

/// Immutable proof carried by a host's prepared instruction-publication token.
/// Implementors may additionally own platform rendezvous/storage guards.
pub trait CacheSync {
    fn executable_ranges(&self) -> &[TargetRange];
    fn scope(&self) -> ExecutionScope;
}
impl CacheSync for PreparedCacheSync {
    fn executable_ranges(&self) -> &[TargetRange] {
        &self.executable_ranges
    }
    fn scope(&self) -> ExecutionScope {
        self.scope
    }
}

/// Host instruction publication. The token must retain the complete ranges and scope.
pub trait CodeCache {
    type Prepared: CacheSync;
    /// Deployment policy: which execution contexts can run the published code.
    fn required_scope(&self) -> ExecutionScope {
        ExecutionScope::CurrentExecutionContext
    }
    fn execution_domain(&self) -> crate::ExecutionDomainId;
    fn prepare(
        &mut self,
        ranges: &[TargetRange],
        scope: ExecutionScope,
    ) -> LoadResult<Self::Prepared>;
    fn synchronize(&mut self, prepared: Self::Prepared) -> LoadResult<()>;
}

/// Explicit cache-coherent host adapter, also used by metadata-only fixtures.
#[derive(Default)]
pub struct CoherentCodeCache;
impl CodeCache for CoherentCodeCache {
    type Prepared = PreparedCacheSync;
    fn execution_domain(&self) -> crate::ExecutionDomainId {
        crate::ExecutionDomainId::FLAT
    }
    fn prepare(
        &mut self,
        ranges: &[TargetRange],
        scope: ExecutionScope,
    ) -> LoadResult<PreparedCacheSync> {
        PreparedCacheSync::try_new(ranges, scope, CacheMaintenance::CoherentInstructionCache)
    }
    fn synchronize(&mut self, _prepared: PreparedCacheSync) -> LoadResult<()> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

fn cache_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}

fn cache_capability_error() -> LoadError {
    LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
}

fn cache_contract_error(executable_ranges: &[TargetRange]) -> LoadError {
    let range = executable_ranges
        .first()
        .copied()
        .unwrap_or(TargetRange::new(TargetAddress::new(0), 0));
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::TargetRange {
            start: range.start(),
            len: range.len(),
            align: 0,
        },
    )
}
