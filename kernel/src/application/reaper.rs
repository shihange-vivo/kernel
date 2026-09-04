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

use blueos_loader::{ImageMemory, LinkProduct};

use crate::application::{
    adapters::flat_memory::FlatImageMemory,
    group::{ThreadGroup, ThreadGroupError},
    publication::KernelLinkReceipt,
    registry::SystemDsoRegistry,
};

/// The observable result of one reap (§18.5 oracle).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReapReport {
    /// Number of private (root and session-private) image leases released.
    pub private_images: usize,
    /// Number of counted imported DSO references dropped and resolved.
    pub imported_dsos: usize,
}

/// A cloneable handle that reaps drained application groups (§16.4).
pub struct ApplicationReaper {
    registry: SystemDsoRegistry,
    memory: FlatImageMemory,
}

impl ApplicationReaper {
    /// Build a reaper over the shared registry and shared-flat memory service.
    pub fn new(registry: SystemDsoRegistry, memory: FlatImageMemory) -> Self {
        Self { registry, memory }
    }

    /// Take the group's resources and release every private image exactly once,
    /// resolving the quiescence of every imported DSO this application held
    /// (§16.4). Returns [`ThreadGroupError`] when the group is not yet ready to
    /// reap (still draining, members remain, fini pending, or already reaped).
    pub fn reap(&self, group: &ThreadGroup) -> Result<ReapReport, ThreadGroupError> {
        let product: LinkProduct<KernelLinkReceipt> = group.take_resources_for_reap()?;
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
