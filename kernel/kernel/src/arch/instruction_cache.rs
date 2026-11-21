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

//! Publish newly written instructions before the kernel hands off execution.

use core::ops::Range;
#[cfg(smp)]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(smp)]
const NUM_CORES: usize = blueos_kconfig::CONFIG_NUM_CORES as usize;
#[cfg(smp)]
static SYNC_PENDING: [AtomicBool; NUM_CORES] = [const { AtomicBool::new(false) }; NUM_CORES];

/// Synchronize instruction writes on this CPU and request synchronization
/// before other CPUs execute the range.
///
/// # Safety
/// The caller must keep the range mapped and stay on the current CPU during
/// maintenance. On AArch64 the range must be inner-shareable normal memory.
/// Publish the range before making it available to any executing context.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv32",
    target_arch = "riscv64"
))]
pub(crate) unsafe fn publish(range: Range<usize>) {
    if range.is_empty() {
        return;
    }

    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    // SAFETY: order prior stores before other harts can observe a pending fence.
    // The local fence completes publication on this hart.
    unsafe {
        #[cfg(smp)]
        core::arch::asm!("fence rw, rw", options(nostack, preserves_flags));
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }

    #[cfg(target_arch = "aarch64")]
    {
        let ctr_el0: u64;
        // SAFETY: the kernel has access to the cache type register.
        unsafe {
            core::arch::asm!("mrs {value}, ctr_el0", value = out(reg) ctr_el0, options(nostack));
        }
        let data_line = 4usize << ((ctr_el0 >> 16) & 0xf);
        let instruction_line = 4usize << (ctr_el0 & 0xf);

        let mut address = range.start & !(data_line - 1);
        while address < range.end {
            // SAFETY: the line intersects the caller's live, mapped range.
            unsafe {
                core::arch::asm!("dc cvau, {address}", address = in(reg) address, options(nostack, preserves_flags))
            };
            address = address.saturating_add(data_line);
        }
        // SAFETY: wait for the data cache cleans before instruction invalidation.
        unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };

        address = range.start & !(instruction_line - 1);
        while address < range.end {
            // SAFETY: the line intersects the same inner-shareable range.
            unsafe {
                core::arch::asm!("ic ivau, {address}", address = in(reg) address, options(nostack, preserves_flags))
            };
            address = address.saturating_add(instruction_line);
        }
        // SAFETY: complete invalidation and synchronize local instruction fetch.
        unsafe { core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    }

    #[cfg(smp)]
    {
        let current_cpu = super::current_cpu_id();
        for (cpu, pending) in SYNC_PENDING.iter().enumerate() {
            if cpu != current_cpu {
                // RMWs preserve earlier publications when multiple writers
                // mark the same CPU before it synchronizes.
                pending.swap(true, Ordering::AcqRel);
            }
        }
    }
}

/// Complete pending publication on this CPU before transferring execution.
/// The caller keeps local interrupts masked through this operation.
#[cfg(smp)]
#[inline]
pub(crate) fn synchronize_pending() {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv32",
        target_arch = "riscv64"
    ))]
    {
        debug_assert!(!super::local_irq_enabled());
        let pending = &SYNC_PENDING[super::current_cpu_id()];
        // The ready or deferred queue handoff orders publication before this
        // check. Only this CPU clears its flag, with local interrupts masked.
        if pending.load(Ordering::Relaxed) && pending.swap(false, Ordering::AcqRel) {
            #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
            // SAFETY: complete the publisher's data-to-instruction ordering on this hart.
            unsafe {
                core::arch::asm!("fence.i", options(nostack, preserves_flags));
            }
            #[cfg(target_arch = "aarch64")]
            // SAFETY: the publisher completed cache maintenance before setting the flag.
            unsafe {
                core::arch::asm!("isb", options(nostack, preserves_flags));
            }
        }
    }
}

#[cfg(all(
    test,
    smp,
    any(
        target_arch = "aarch64",
        target_arch = "riscv32",
        target_arch = "riscv64"
    )
))]
mod tests {
    use super::*;
    use crate::support::DisableInterruptGuard;
    use blueos_test_macro::test;

    #[test]
    fn publication_only_requests_instruction_synchronization_on_other_cpus() {
        let _irq = DisableInterruptGuard::new();
        let pending = &SYNC_PENDING[crate::arch::current_cpu_id()];
        synchronize_pending();

        let entry = synchronize_pending as *const () as usize;
        // SAFETY: this kernel instruction is mapped throughout the operation.
        unsafe { publish(entry..entry + 1) };
        assert!(!pending.load(Ordering::Relaxed));

        // A publisher on another CPU would mark this CPU pending.
        pending.swap(true, Ordering::AcqRel);
        synchronize_pending();
        assert!(!pending.load(Ordering::Relaxed));
    }
}
