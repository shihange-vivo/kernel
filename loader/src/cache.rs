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

use crate::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage, TargetRange};

pub trait CodeCache {
    fn synchronize(&mut self, runtime_range: TargetRange) -> LoadResult<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ArchitectureCodeCache;

impl CodeCache for ArchitectureCodeCache {
    fn synchronize(&mut self, runtime_range: TargetRange) -> LoadResult<()> {
        runtime_range.end()?;

        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        unsafe {
            core::arch::asm!("fence.i", options(nostack));
            Ok(())
        }

        #[cfg(target_arch = "arm")]
        unsafe {
            core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
            Ok(())
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            synchronize_aarch64(runtime_range)
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        #[cfg(not(any(
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "x86",
            target_arch = "x86_64"
        )))]
        Err(cache_error(runtime_range))
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
        address = address
            .checked_add(dcache_line)
            .ok_or_else(|| cache_error(runtime_range))?;
    }
    core::arch::asm!("dsb ish", options(nostack));

    address = runtime_range.start().align_down(icache_line)?.get();
    while address < end {
        core::arch::asm!("ic ivau, {address}", address = in(reg) address, options(nostack));
        address = address
            .checked_add(icache_line)
            .ok_or_else(|| cache_error(runtime_range))?;
    }
    core::arch::asm!("dsb ish", "isb", options(nostack));
    Ok(())
}

fn cache_error(runtime_range: TargetRange) -> LoadError {
    LoadError::new(
        LoadStage::Cache,
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::TargetRange {
            start: runtime_range.start(),
            len: runtime_range.len(),
        },
    )
}
