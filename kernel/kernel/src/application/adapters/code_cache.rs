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

//! Native instruction publication for the kernel's flat execution domain.
//!
//! Shared by application loading and loader integration tests. This adapter
//! is built with the application module when dynamic loading is enabled.

use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    memory::{
        CacheMaintenance, CacheRequirements, CodeCache, ExecutionScope, PreparedCacheSync,
        TargetRange,
    },
    ExecutionDomainId, LoadError, LoadResult,
};

pub struct ArchitectureCodeCache {
    requirements: CacheRequirements,
}

impl ArchitectureCodeCache {
    #[inline]
    pub const fn new(requirements: CacheRequirements) -> Self {
        Self { requirements }
    }
    pub fn requirements(&self) -> CacheRequirements {
        self.requirements
    }

    fn prepare(&self, executable_ranges: &[TargetRange]) -> LoadResult<PreparedCacheSync> {
        let (scope, maintenance) = architecture_cache_capability()?;
        PreparedCacheSync::try_new(executable_ranges, scope, maintenance)
    }

    fn synchronize(&mut self, prepared: PreparedCacheSync) -> LoadResult<()> {
        let (scope, maintenance) = architecture_cache_capability()?;
        if prepared.scope() != scope || prepared.maintenance() != maintenance {
            return Err(cache_capability_error());
        }
        let Some(first_range) = prepared.executable_ranges().first().copied() else {
            return Ok(());
        };

        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        unsafe {
            core::arch::asm!("fence.i", options(nostack));
        }

        #[cfg(all(target_arch = "arm", armv7m))]
        unsafe {
            core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
        }

        #[cfg(all(target_arch = "arm", not(armv7m)))]
        for range in prepared.executable_ranges() {
            unsafe { synchronize_arm_v8m(*range)? };
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
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "aarch64"
        )))]
        return Err(cache_error(first_range));

        Ok(())
    }
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

fn architecture_cache_capability() -> LoadResult<(ExecutionScope, CacheMaintenance)> {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    return Ok((
        ExecutionScope::CurrentExecutionContext,
        CacheMaintenance::InstructionFence,
    ));

    #[cfg(all(target_arch = "arm", armv7m))]
    return Ok((
        ExecutionScope::CurrentExecutionContext,
        CacheMaintenance::BarrierOnly,
    ));

    // Cache-enabled ARMv8-M performs a D-cache clean to PoU followed by an
    // I-cache invalidate to PoU for every executable byte. This remains
    // current-core scope; an SMP Cortex-M product must provide a rendezvous
    // adapter before advertising AllExecutionContexts.
    #[cfg(all(target_arch = "arm", not(armv7m)))]
    return Ok((
        ExecutionScope::CurrentExecutionContext,
        CacheMaintenance::CleanAndInvalidate,
    ));

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

/// Publish freshly written code on cache-enabled Cortex-M implementations.
///
/// ARMv8-M Mainline exposes cache maintenance through the System Control
/// Block. `DCCMVAU` cleans a data-cache line to the point of unification and
/// `ICIMVAU` invalidates the corresponding instruction-cache line. Cortex-M55
/// has 32-byte I/D cache lines. Cacheless
/// implementations define these maintenance writes as harmless; the barriers
/// still establish the required instruction synchronization boundary.
///
/// # Safety
///
/// The caller runs in privileged kernel context on ARMv8-M and supplies ranges
/// already validated by the loader. The two MMIO addresses are architectural
/// SCB registers, not application-controlled pointers.
#[cfg(all(target_arch = "arm", not(armv7m)))]
unsafe fn synchronize_arm_v8m(runtime_range: TargetRange) -> LoadResult<()> {
    const CACHE_LINE_BYTES: u64 = 32;
    const SCB_ICIMVAU: *mut u32 = 0xE000_EF58 as *mut u32;
    const SCB_DCCMVAU: *mut u32 = 0xE000_EF64 as *mut u32;

    let end = runtime_range.end()?.get();
    let mut address = runtime_range.start().align_down(CACHE_LINE_BYTES)?.get();

    core::arch::asm!("dsb", options(nostack, preserves_flags));
    while address < end {
        let mva = u32::try_from(address).map_err(|_| cache_error(runtime_range))?;
        core::ptr::write_volatile(SCB_DCCMVAU, mva);
        address = address
            .checked_add(CACHE_LINE_BYTES)
            .ok_or_else(|| cache_error(runtime_range))?;
    }
    core::arch::asm!("dsb", options(nostack, preserves_flags));

    address = runtime_range.start().align_down(CACHE_LINE_BYTES)?.get();
    while address < end {
        let mva = u32::try_from(address).map_err(|_| cache_error(runtime_range))?;
        core::ptr::write_volatile(SCB_ICIMVAU, mva);
        address = address
            .checked_add(CACHE_LINE_BYTES)
            .ok_or_else(|| cache_error(runtime_range))?;
    }
    core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
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

impl CodeCache for ArchitectureCodeCache {
    type Prepared = PreparedCacheSync;
    fn required_scope(&self) -> ExecutionScope {
        self.requirements.scope()
    }
    fn execution_domain(&self) -> ExecutionDomainId {
        ExecutionDomainId::FLAT
    }
    fn prepare(
        &mut self,
        ranges: &[TargetRange],
        scope: ExecutionScope,
    ) -> LoadResult<PreparedCacheSync> {
        let prepared = ArchitectureCodeCache::prepare(self, ranges)?;
        if !prepared.scope().covers(scope) {
            return Err(cache_capability_error());
        }
        Ok(prepared)
    }
    fn synchronize(&mut self, prepared: PreparedCacheSync) -> LoadResult<()> {
        ArchitectureCodeCache::synchronize(self, prepared)
    }
}

fn cache_capability_error() -> LoadError {
    LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
}
