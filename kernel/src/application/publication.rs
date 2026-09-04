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

//! Kernel-side link publication (C26, §15).
//!
//! [`KernelLinkPublisher`] is the [`LinkPublisher`] the `ApplicationLoader`
//! drives the staged `DynamicLinker::publish` with. Its receipt —
//! [`KernelLinkReceipt`] — is the long-term owner of every raw
//! [`AllocationLease`](blueos_loader::AllocationLease) the link session
//! produced, split by residency:
//!
//! * `private_allocations` hold the executable root (and any session-private
//!   image); they are released by the group reaper when the application
//!   terminates (§16.4).
//! * `system_allocations` hold the first-loading system DSO candidates; Phase 1
//!   ties their raw lease to the first publishing group, so they stay mapped
//!   until that group reaps — a conservative residency that never releases code
//!   still reachable through a live import (§13.3).
//!
//! `prepare_batch` performs the only fallible work: it proves the target group
//! has no link product yet, derives the private/system residency of each
//! rollback-log lease from the manifest's explicit `ImageOwnership`, and
//! pre-reserves the commit sinks. The leases arrive in `commit_batch` in
//! creation order (the same order the manifest's non-imported entries list), so
//! `commit_batch` only partitions — it never allocates, validates or fails.

use alloc::vec::Vec;

use blueos_loader::{
    AllocationLease, CommittingLinkProduct, ErrorContext, ImageOwnership, LinkPublisher,
    LoadError, LoadErrorKind, LoadResult, PreparedLinkManifest,
};

use crate::application::group::{GroupState, ThreadGroup};

/// The long-term owner of a committed link's raw allocation leases (§15.1).
///
/// The counted [`SystemDsoLease`](crate::application::registry::SystemDsoLease)
/// set a link acquires for its *imported* Ready DSOs is not carried here: those
/// references are minted by the resolver after the link resolves and are moved
/// into the application's start storage by the loader (C26-b), alongside the
/// link-map generation.
pub struct KernelLinkReceipt {
    private_allocations: Vec<AllocationLease>,
    system_allocations: Vec<AllocationLease>,
}

impl KernelLinkReceipt {
    /// The root and session-private image leases, released on reaping (§16.4).
    #[inline]
    pub fn private_allocations(&self) -> &[AllocationLease] {
        &self.private_allocations
    }

    /// The first-loading system DSO leases, held until the first publisher reaps.
    #[inline]
    pub fn system_allocations(&self) -> &[AllocationLease] {
        &self.system_allocations
    }
}

/// Fallible state produced by [`KernelLinkPublisher::prepare_batch`].
///
/// `owners` records the residency of each rollback-log lease in creation order;
/// `private`/`system` are the pre-reserved commit sinks so `commit_batch` can
/// partition the leases without allocating.
pub struct KernelLinkPreparedBatch {
    owners: Vec<ImageOwnership>,
    private: Vec<AllocationLease>,
    system: Vec<AllocationLease>,
}

/// The kernel publication boundary (S9, §15.1).
///
/// `prepare_batch` re-verifies the target group is still unlinked and
/// precomputes the private/system split from the manifest; `commit_batch` then
/// only moves the leases into their owning side of the receipt.
pub struct KernelLinkPublisher {
    group: ThreadGroup,
}

impl KernelLinkPublisher {
    /// Build a publisher that will publish into `group`.
    pub fn new(group: ThreadGroup) -> Self {
        Self { group }
    }

    /// The group this publisher installs into, for the `ApplicationLoader` to
    /// complete the two-phase install after `publish` returns.
    pub fn group(&self) -> &ThreadGroup {
        &self.group
    }
}

impl LinkPublisher for KernelLinkPublisher {
    type PreparedBatch = KernelLinkPreparedBatch;
    type Receipt = KernelLinkReceipt;

    fn prepare_batch(&mut self, manifest: &PreparedLinkManifest) -> LoadResult<Self::PreparedBatch> {
        // The group must not already carry a link product: a second install
        // would expose a half-written link map to a reader (§15.2).
        if self.group.state() != GroupState::New {
            return Err(publish_error());
        }

        // The rollback log drains in creation order, which is exactly the order
        // the manifest lists loaded images (the root id 0 first, then each
        // discovered dependency in id order); imported Ready images carry no
        // lease and are skipped here (§12.1). Record the residency of each
        // lease so `commit_batch` can partition without re-deriving it, and
        // reserve the commit sinks up front.
        let mut owners = Vec::new();
        let mut private_cap = 0usize;
        let mut system_cap = 0usize;
        for entry in manifest.link_map() {
            let ownership = entry.ownership();
            if ownership == ImageOwnership::ExternalReady {
                continue;
            }
            owners.try_reserve(1).map_err(|_| publish_oom())?;
            owners.push(ownership);
            if ownership == ImageOwnership::SessionPrivate {
                private_cap += 1;
            } else {
                system_cap += 1;
            }
        }

        let mut private = Vec::new();
        private.try_reserve_exact(private_cap).map_err(|_| publish_oom())?;
        let mut system = Vec::new();
        system.try_reserve_exact(system_cap).map_err(|_| publish_oom())?;

        Ok(KernelLinkPreparedBatch {
            owners,
            private,
            system,
        })
    }

    /// # Safety
    ///
    /// `prepared` and `product` come from the same live link session on this
    /// publisher; the `prepare_batch` check already proved the group is unlinked.
    unsafe fn commit_batch(
        &mut self,
        prepared: Self::PreparedBatch,
        product: CommittingLinkProduct,
    ) -> Self::Receipt {
        let KernelLinkPreparedBatch {
            owners,
            mut private,
            mut system,
        } = prepared;
        let leases = product.into_leases();
        debug_assert_eq!(leases.len(), owners.len());
        for (lease, ownership) in leases.into_iter().zip(owners) {
            match ownership {
                ImageOwnership::SessionPrivate => private.push(lease),
                ImageOwnership::SystemCandidate => system.push(lease),
                // `prepare_batch` skipped imported Ready images; a lease should
                // never carry that residency here.
                ImageOwnership::ExternalReady => {
                    unreachable!("imported images carry no lease")
                }
            }
        }
        KernelLinkReceipt {
            private_allocations: private,
            system_allocations: system,
        }
    }
}

fn publish_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}

fn publish_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}
