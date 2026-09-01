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

use alloc::vec::Vec;

use crate::{
    address::{TargetAddress, TargetRange},
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionScope {
    CurrentExecutionContext,
    AllExecutionContexts,
}

impl ExecutionScope {
    fn covers(self, required: Self) -> bool {
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
    maintenance: Option<CacheMaintenance>,
}

impl CacheRequirements {
    pub const CURRENT_EXECUTION_CONTEXT: Self = Self::new(ExecutionScope::CurrentExecutionContext);

    pub const fn new(scope: ExecutionScope) -> Self {
        Self {
            scope,
            maintenance: None,
        }
    }

    pub const fn exact(scope: ExecutionScope, maintenance: CacheMaintenance) -> Self {
        Self {
            scope,
            maintenance: Some(maintenance),
        }
    }

    pub const fn scope(self) -> ExecutionScope {
        self.scope
    }

    pub const fn maintenance(self) -> Option<CacheMaintenance> {
        self.maintenance
    }

    pub fn validate_prepared(
        self,
        executable_ranges: &[TargetRange],
        prepared: &PreparedCacheSync,
    ) -> LoadResult<()> {
        if prepared.executable_ranges() != executable_ranges {
            return Err(cache_contract_error(executable_ranges));
        }
        let scope_valid = prepared.scope().covers(self.scope);
        let maintenance_valid = self
            .maintenance
            .is_none_or(|required| prepared.maintenance() == required);
        if scope_valid && maintenance_valid {
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

    pub fn complete(self) -> CacheSyncOutcome {
        CacheSyncOutcome {
            executable_ranges: self.executable_ranges,
            scope: self.scope,
            maintenance: self.maintenance,
        }
    }
}

#[derive(Debug)]
pub struct CacheSyncOutcome {
    executable_ranges: Vec<TargetRange>,
    scope: ExecutionScope,
    maintenance: CacheMaintenance,
}

impl CacheSyncOutcome {
    pub fn executable_ranges(&self) -> &[TargetRange] {
        &self.executable_ranges
    }

    pub const fn scope(&self) -> ExecutionScope {
        self.scope
    }

    pub const fn maintenance(&self) -> CacheMaintenance {
        self.maintenance
    }

    pub(crate) fn validate_completion(
        &self,
        executable_ranges: &[TargetRange],
        prepared_scope: ExecutionScope,
        prepared_maintenance: CacheMaintenance,
    ) -> LoadResult<()> {
        if self.executable_ranges() == executable_ranges
            && self.scope() == prepared_scope
            && self.maintenance() == prepared_maintenance
        {
            Ok(())
        } else {
            Err(cache_contract_error(executable_ranges))
        }
    }
}

pub trait CodeCache {
    fn requirements(&self) -> CacheRequirements;

    fn prepare(&self, executable_ranges: &[TargetRange]) -> LoadResult<PreparedCacheSync>;

    fn synchronize(&mut self, prepared: PreparedCacheSync) -> LoadResult<CacheSyncOutcome>;
}

impl<C: CodeCache + ?Sized> CodeCache for &mut C {
    fn requirements(&self) -> CacheRequirements {
        (**self).requirements()
    }

    fn prepare(&self, executable_ranges: &[TargetRange]) -> LoadResult<PreparedCacheSync> {
        (**self).prepare(executable_ranges)
    }

    fn synchronize(&mut self, prepared: PreparedCacheSync) -> LoadResult<CacheSyncOutcome> {
        (**self).synchronize(prepared)
    }
}

pub(crate) struct ArchitectureCodeCache {
    requirements: CacheRequirements,
}

impl ArchitectureCodeCache {
    #[inline]
    pub const fn new(requirements: CacheRequirements) -> Self {
        Self { requirements }
    }
}

impl CodeCache for ArchitectureCodeCache {
    fn requirements(&self) -> CacheRequirements {
        self.requirements
    }

    fn prepare(&self, executable_ranges: &[TargetRange]) -> LoadResult<PreparedCacheSync> {
        let (scope, maintenance) = architecture_cache_capability()?;
        PreparedCacheSync::try_new(executable_ranges, scope, maintenance)
    }

    fn synchronize(&mut self, prepared: PreparedCacheSync) -> LoadResult<CacheSyncOutcome> {
        let (scope, maintenance) = architecture_cache_capability()?;
        if prepared.scope() != scope || prepared.maintenance() != maintenance {
            return Err(cache_capability_error());
        }
        let Some(first_range) = prepared.executable_ranges().first().copied() else {
            return Ok(prepared.complete());
        };

        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        unsafe {
            core::arch::asm!("fence.i", options(nostack));
        }

        #[cfg(target_arch = "arm")]
        unsafe {
            core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
        }

        #[cfg(target_arch = "aarch64")]
        for range in prepared.executable_ranges() {
            unsafe { synchronize_aarch64(*range)? };
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }

        #[cfg(not(any(
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "x86",
            target_arch = "x86_64"
        )))]
        return Err(cache_error(first_range));

        Ok(prepared.complete())
    }
}

fn architecture_cache_capability() -> LoadResult<(ExecutionScope, CacheMaintenance)> {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    return Ok((
        ExecutionScope::CurrentExecutionContext,
        CacheMaintenance::InstructionFence,
    ));

    #[cfg(all(target_arch = "arm", target_board = "qemu_mps2_an385"))]
    return Ok((
        ExecutionScope::CurrentExecutionContext,
        CacheMaintenance::BarrierOnly,
    ));

    #[cfg(all(target_arch = "arm", not(target_board = "qemu_mps2_an385")))]
    return Err(cache_capability_error());

    #[cfg(target_arch = "aarch64")]
    return Ok((
        ExecutionScope::CurrentExecutionContext,
        CacheMaintenance::CleanAndInvalidate,
    ));

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    return Ok((
        ExecutionScope::AllExecutionContexts,
        CacheMaintenance::CoherentInstructionCache,
    ));

    #[allow(unreachable_code)]
    Err(cache_capability_error())
}

#[cfg(target_arch = "aarch64")]
unsafe fn synchronize_aarch64(runtime_range: TargetRange) -> LoadResult<()> {
    let mut ctr_el0: u64;
    core::arch::asm!("mrs {value}, ctr_el0", value = out(reg) ctr_el0, options(nostack));
    let dcache_line = 4_u64 << ((ctr_el0 >> 16) & 0xf);
    let icache_line = 4_u64 << (ctr_el0 & 0xf);
    let end = runtime_range.end()?.get();

    let mut address = runtime_range.start().align_down(dcache_line)?.get();
    while address < end {
        core::arch::asm!("dc cvau, {address}", address = in(reg) address, options(nostack));
        address = address.saturating_add(dcache_line);
    }
    core::arch::asm!("dsb ish", options(nostack));

    address = runtime_range.start().align_down(icache_line)?.get();
    while address < end {
        core::arch::asm!("ic ivau, {address}", address = in(reg) address, options(nostack));
        address = address.saturating_add(icache_line);
    }
    core::arch::asm!("dsb ish", "isb", options(nostack));
    Ok(())
}
fn cache_error(runtime_range: TargetRange) -> LoadError {
    LoadError::new(
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::TargetRange {
            start: runtime_range.start(),
            len: runtime_range.len(),
            align: 0,
        },
    )
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
