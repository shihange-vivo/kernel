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

//! Deferred application reaper: release a drained group's resources (C27, §16.4).
//!
//! [`ApplicationReaper`] is the consuming counterpart to [`ApplicationLoader`]:
//! a cloneable handle onto the shared registry and the shared-flat memory
//! service. Once the exit coordinator has driven a group to `Draining`, all its
//! member threads have left and the fini plan is resolved, the reaper takes the
//! group's link product, releases the private (root) image leases, drops the
//! counted imported DSO leases, and resolves each resulting registry quiescence
//! (§16.4).
//!
//! Phase 1 is *conservatively resident* (§13.3): a system DSO that was first
//! loaded by some application, or that another application imported, is never
//! unloaded here. The first-loading raw allocation lease and the `Ready`
//! descriptor it backs stay mapped so a later import can reuse the exact same
//! instance without a reload; proving quiescence and unloading (generation + 1)
//! is deferred to the C29 fixture. This reaper therefore never releases a
//! system allocation lease, only the counted imported references, whose
//! `Drop` moves a zero-lease slot to `Quiescing` and is resolved back to a
//! cached `Ready` by [`SystemDsoRegistry::resolve_quiescence`](super::registry::SystemDsoRegistry::resolve_quiescence).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use blueos_loader::{ImageMemory, LinkProduct};

use crate::{
    application::{
        adapters::flat_memory::FlatImageMemory,
        group::{GroupState, ThreadGroup, ThreadGroupError},
        manager::ApplicationManager,
        publication::KernelLinkReceipt,
        registry::SystemDsoRegistry,
    },
    thread::{self, Builder, Entry},
};

/// The observable result of one reap (§18.5 oracle).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReapReport {
    /// Number of private (root and session-private) image leases released.
    pub private_images: usize,
    /// Number of counted imported DSO references dropped and resolved.
    pub imported_dsos: usize,
}

/// The bound between two reaper scans: the thread parks on an atomic wait with
/// this timeout, then re-checks every pending group. Member exits and lifecycle
/// transitions are all lock-free observable state, so a short bounded poll is
/// the honest MVP wait primitive; registration still wakes the thread promptly
/// (§16.4).
const REAPER_POLL_MILLIS: u64 = 10;

/// A cloneable handle that reaps drained application groups (§16.4).
#[derive(Clone)]
pub struct ApplicationReaper {
    registry: SystemDsoRegistry,
    memory: FlatImageMemory,
    /// Every group a launch handed over — successfully or failed — waiting to
    /// be reaped once its members left and its fini resolved.
    pending: Arc<spin::Mutex<Vec<ThreadGroup>>>,
    /// Bumped (and woken) on registration so the reaper thread notices new
    /// work without waiting out its poll bound.
    wake: Arc<AtomicUsize>,
}

impl ApplicationReaper {
    /// Build a reaper over the shared registry and shared-flat memory service.
    pub fn new(registry: SystemDsoRegistry, memory: FlatImageMemory) -> Self {
        Self {
            registry,
            memory,
            pending: Arc::new(spin::Mutex::new(Vec::new())),
            wake: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Hand a launched group to the reaper for eventual resource release
    /// (§16.4). The group stays watched until its members left, its fini
    /// resolved and its resources were taken; failed launches hand their group
    /// over the same way.
    pub fn register(&self, group: &ThreadGroup) {
        self.pending.lock().push(group.clone());
        self.wake.fetch_add(1, Ordering::Release);
        let _ = crate::sync::atomic_wake(&self.wake, usize::MAX);
    }

    /// Spawn the kernel reaper thread. It owns clones of the reaper and the
    /// manager and never returns (§16.4: the reaper releases resources outside
    /// every registry/manager lock).
    pub fn spawn(&self, manager: ApplicationManager) {
        let reaper = self.clone();
        let thread = Builder::new(Entry::Closure(Box::new(move || reaper.run(manager))))
            .build();
        let queued = crate::scheduler::queue_ready_thread(thread::IDLE, thread);
        debug_assert!(queued.is_ok(), "reaper thread must queue");
    }

    /// The reaper thread body: scan every pending group, reap the ones whose
    /// members left and whose fini resolved, then park for a bounded interval
    /// and repeat.
    fn run(&self, manager: ApplicationManager) -> ! {
        loop {
            self.scan(&manager);
            let epoch = self.wake.load(Ordering::Acquire);
            // A bounded wait: member exits and lifecycle transitions are plain
            // shared state with no wake plumbing into this thread, so the poll
            // bound is what makes the reaper eventually observe them (§16.4).
            let _ = crate::sync::atomic_wait(
                &self.wake,
                epoch,
                crate::time::Tick::from_millis(REAPER_POLL_MILLIS),
            );
        }
    }

    /// One pass over every pending group.
    fn scan(&self, manager: &ApplicationManager) {
        let mut pending = self.pending.lock();
        pending.retain(|group| !self.try_reap(group, manager));
    }

    /// Advance one group towards reaping and return `true` once it is fully
    /// reaped (and may leave the pending set). Covers the three terminal
    /// shapes (§16.4):
    ///
    /// - `New`: the launch failed before installing a product; nothing to
    ///   release, only the manager's `Failed` slot to recycle.
    /// - `Linked` with no members: the main thread died without reporting
    ///   exit; force the abnormal drain with a skipped fini and fall through.
    /// - `Draining` with no members and a pending fini: the coordinator died
    ///   mid-atexit; skip the fini and fall through.
    /// - `Draining` with no members and a resolved fini: take the resources,
    ///   release the private images, drop the imported leases, close the
    ///   manager lifecycle and recycle the slot.
    fn try_reap(&self, group: &ThreadGroup, manager: &ApplicationManager) -> bool {
        match group.state() {
            GroupState::Reaped => return true,
            GroupState::New => {
                // No product was installed; only the manager slot (Failed)
                // needs recycling.
                return self.finish_slot(group, manager);
            }
            GroupState::Linked => {
                if !group.is_empty() {
                    return false;
                }
                // Main thread died without ApplicationBeginExit: abnormal
                // drain, destructors are skipped with a recorded reason
                // (§16.4).
                let _ = group.begin_exit();
                let _ = group.skip_fini();
            }
            GroupState::Draining => {
                if !group.is_empty() {
                    return false;
                }
                if !group.fini_resolved() {
                    // Coordinator died between BeginExit and FinishExit:
                    // skip the destructor plan and fall through (§16.4).
                    let _ = group.skip_fini();
                }
            }
        }
        match self.reap(group) {
            Ok(report) => {
                // C29 oracle (§18.5): the checker asserts the private image
                // count and the imported-DSO count of every reap.
                if let Some(handle) = group.handle() {
                    log::info!(
                        "APP_REAP handle={}:{} private_images={} imported_dsos={}",
                        handle.slot,
                        handle.generation,
                        report.private_images,
                        report.imported_dsos
                    );
                }
            }
            Err(_) => {
                // Not ready after all (a member raced back in); retry next
                // scan.
                return false;
            }
        }
        self.finish_slot(group, manager)
    }

    /// Close the manager lifecycle for a fully reaped group and recycle the
    /// slot (§14.4).
    fn finish_slot(&self, group: &ThreadGroup, manager: &ApplicationManager) -> bool {
        let Some(handle) = group.handle() else {
            // A group without a handle never entered the manager slot table;
            // nothing to recycle.
            return true;
        };
        let _ = manager.finish(handle);
        let _ = manager.release(handle);
        true
    }

    /// Take the group's resources and release every private image exactly once,
    /// resolving the quiescence of every imported DSO this application held
    /// (§16.4). Returns [`ThreadGroupError`] when the group is not yet ready to
    /// reap (still draining, members remain, fini pending, or already reaped).
    pub fn reap(&self, group: &ThreadGroup) -> Result<ReapReport, ThreadGroupError> {
        let (product, start_storage) = group.take_resources_for_reap()?;
        // The start storage holds no leases; dropping it releases the pinned
        // argv/envp/auxv/init/fini backing once no thread can read it.
        drop(start_storage);
        let receipt = product.into_publication();
        let (private, _system, system_leases) = receipt.into_parts();

        // `FlatImageMemory` is a handle onto a shared service; `release_committed`
        // needs `&mut self`, so release through a per-call clone like the loader's
        // link session does (`let mut memory = self.memory.clone()`).
        let mut memory = self.memory.clone();
        let private_images = private.len();
        for lease in private {
            memory.release_committed(lease);
        }

        // `_system` (the first-loading raw leases) are intentionally dropped
        // without release: Phase 1 keeps every system DSO resident so a later
        // import reuses the same mapped instance (§13.3). Dropping the raw
        // lease is a no-op on the backing (the allocation entry remains in the
        // shared service); no `release_committed`/`abort_image` call happens.
        drop(_system);

        let imported_dsos = system_leases.len();
        for lease in system_leases {
            let domain = lease.domain();
            // Record the address before the lease drops: `Drop` may move the
            // slot to `Quiescing`, which retains the SONAME, but the reaper must
            // resolve using the values it held, not a stale reference.
            let soname = lease.soname().clone();
            drop(lease);
            // KeepCached: the last counted reference is gone but the image stays
            // mapped and importable (§13.3). The slot returns to `Ready` with
            // zero leases rather than being unloaded.
            self.registry.resolve_quiescence(domain, &soname, true);
        }

        Ok(ReapReport {
            private_images,
            imported_dsos,
        })
    }
}
