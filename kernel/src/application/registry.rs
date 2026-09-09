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

//! System DSO registry: permit, lease and generation state machine (C24, §13).
//!
//! One [`SystemDsoRegistry`] tracks every mapped system DSO instance per
//! `(LinkDomainId, SONAME)`. It answers the single question a resolver needs:
//! for a requested system dependency, is there already a Ready instance to
//! *import*, or must some link *load* it as a candidate?
//!
//! The state machine (§13.2) is driven by three unique, non-`Clone` tokens:
//!
//! * [`LoadPermit`] — the sole publication authority for one generation, handed
//!   out exactly once while a slot is `Loading`. Dropping it before
//!   [`SystemDsoRegistry::publish_relocated`] cancels the load (back to
//!   `Vacant`).
//! * [`RelocatedPermit`] — the authority handed back by `publish_relocated`
//!   once the link's relocation/seal stage completed. Dropping it before
//!   [`SystemDsoRegistry::mark_ready`] also cancels, because nothing has run a
//!   constructor yet (§13.3).
//! * [`SystemDsoLease`] — one counted reference to a Ready instance. Acquiring
//!   it on the Ready fast path only increments a counter; it never re-maps,
//!   re-relocates or re-runs init (§13.3, §12.5). Its `Drop` only decrements
//!   the counter. A reaper explicitly resolves a zero-user instance through
//!   [`SystemDsoRegistry::resolve_quiescence`]; an ordinary failed-link drop
//!   safely leaves a reusable zero-user `Ready` instance instead of stranding
//!   it in an in-flight state with no worker (§13.3).
//! * [`WaitHandle`] — a waiter's ticket for an in-flight generation. A resolver
//!   that loses the race blocks on it outside any loader/manager lock; the
//!   slot's resolution signal wakes it so it can re-acquire (§13.3, §13.5).
//!
//! The registry keeps no [`AllocationLease`](blueos_loader::AllocationLease)
//! and owns no raw memory: the unique allocation lease for the mapped image
//! lives in the publisher receipt that `mark_ready`'s caller holds, so the
//! reaper reaches the backing through the same `FlatImageMemory` handle
//! (§12.1). The registry is a plain `Arc<Mutex<_>>` handle: the application
//! manager clones it into whichever thread performs a link or a reap, and every
//! slow VFS/link/init step runs *outside* the short registry lock (§14.2).

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use blueos_loader::{
    AllocationLease, DependencyName, ErrorContext, FiniPlan, LinkDomainId, LoadError,
    LoadErrorKind, LoadResult, PublishedImageDescriptor,
};
use spin::Mutex;

use crate::{
    sync::{atomic_wait, atomic_wake},
    time::Tick,
};

/// The outcome of asking the registry for a system dependency (§13.3).
///
/// `Permit` means the caller won the vacant slot and must load the image;
/// `Lease` means a Ready instance already exists and was borrowed;
/// `Pending(handle)` means some other link is mid-construction at the handle's
/// generation, and the caller must block on the handle for that generation to
/// resolve and then re-acquire. A caller never treats `Pending` as "the image
/// is loaded".
pub enum AcquireOutcome {
    Permit(LoadPermit),
    Lease(SystemDsoLease),
    Pending(WaitHandle),
}

/// The outcome of resolving a quiescent slot (C31-d, §8.5).
pub enum QuiescenceResolution {
    /// The zero-lease instance stays `Ready` for a later import.
    KeptCached,
    /// A whole system SCC entered `Unloading`. The worker must run every fini
    /// plan and release every backing before completing the batch.
    Unloaded(SystemUnloadBatch),
}

/// One member handed to the quiescence worker for destruction.
pub struct SystemUnloadBacking {
    pub soname: DependencyName,
    pub allocation: AllocationLease,
    pub fini_plan: FiniPlan,
    /// Outgoing SCC dependency leases. They remain live through this member's
    /// fini and drop only after its backing has been released.
    pub dependencies: Vec<SystemDsoLease>,
}

/// Completion token for an atomically quiesced system SCC.
///
/// Its slots remain `Unloading`, so no new link can observe a partially
/// destroyed group. The worker takes the backings, performs fini/release in
/// ordinary thread context, then calls [`SystemDsoRegistry::finish_unload`].
pub struct SystemUnloadBatch {
    inner: Arc<Mutex<Inner>>,
    slots: Vec<usize>,
    generations: Vec<u32>,
    backings: Vec<SystemUnloadBacking>,
}

impl SystemUnloadBatch {
    pub fn take_backings(&mut self) -> Vec<SystemUnloadBacking> {
        core::mem::take(&mut self.backings)
    }
}

/// The outcome of a batch acquire over a whole declared system closure
/// (C30, §7.3).
pub enum AcquireBatchOutcome {
    /// The entire closure was acquired atomically: `Vacant` slots became
    /// `Loading` (with their permits) and `Ready` slots minted leases.
    Acquired(PreparedSystemBatch),
    /// Some slot is mid-construction; nothing changed and the caller must
    /// wait on the ticket and retry the whole batch.
    Pending(SystemBatchWait),
}

/// The atomically acquired system closure a resolver consumes edge-by-edge.
pub struct PreparedSystemBatch {
    /// First-load candidates: the SONAME paired with its publication permit.
    pub loads: Vec<(DependencyName, LoadPermit)>,
    /// Ready imports: the SONAME, its counted lease and a descriptor clone.
    pub imports: Vec<(DependencyName, SystemDsoLease, PublishedImageDescriptor)>,
}

/// The registry-owned backing of one new system candidate (C31-c, §8.4).
///
/// The first-loading application moves these into the registry at batch
/// publication: the instance — not the application receipt — owns the unique
/// allocation, the descriptor and the fini plan from then on.
pub struct SystemCandidateBacking {
    pub descriptor: PublishedImageDescriptor,
    pub fini_plan: FiniPlan,
    pub allocation: AllocationLease,
    /// Outgoing dependencies to other system SCCs. They become counted leases
    /// atomically when the whole initialization batch becomes Ready.
    pub dependency_names: Vec<DependencyName>,
    /// Empty storage pre-reserved for `dependency_names`, so the Ready
    /// transition and lease minting do not allocate under the registry lock.
    pub dependencies: Vec<SystemDsoLease>,
    /// Every SONAME in this candidate's system SCC. Internal SCC edges are
    /// structural and do not mint self-sustaining leases.
    pub scc_members: Vec<DependencyName>,
    /// Cached/unloadable policy captured from the immutable system catalog.
    pub keep_cached: bool,
}

/// The publication authority for a batch of `Initializing` slots (C31-c,
/// §8.3), minted by [`SystemDsoRegistry::publish_relocated_batch`].
///
/// It must be advanced with [`SystemDsoRegistry::finish_initialization_batch`]
/// once the application reports `ApplicationInitComplete`, or failed through
/// [`SystemDsoRegistry::fail_initialization_batch`] when the application dies
/// first. Dropping it armed fails the batch: no descriptor is ever published
/// and the backings move to `Failed` for the C31-d worker.
pub struct SystemInitBatch {
    inner: Arc<Mutex<Inner>>,
    slots: Vec<usize>,
    generations: Vec<u32>,
    armed: bool,
}

impl SystemInitBatch {
    fn consume(mut self) -> (Arc<Mutex<Inner>>, Vec<usize>, Vec<u32>) {
        self.armed = false;
        (
            Arc::clone(&self.inner),
            core::mem::take(&mut self.slots),
            core::mem::take(&mut self.generations),
        )
    }
}

impl Drop for SystemInitBatch {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // The application never completed its init: fail the batch through
        // the registry so no half-initialized descriptor is published.
        let registry = SystemDsoRegistry {
            inner: Arc::clone(&self.inner),
        };
        let slots = core::mem::take(&mut self.slots);
        let generations = core::mem::take(&mut self.generations);
        registry.fail_initialization_batch(SystemInitBatch {
            inner: Arc::clone(&registry.inner),
            slots,
            generations,
            armed: true,
        });
    }
}

/// A batch waiter's ticket for an in-flight system closure (C30, §7.3).
///
/// The handle keys off the registry-wide resolution epoch, so a wake that
/// resolves only *part* of the closure still causes a safe whole-batch
/// re-check.
pub struct SystemBatchWait {
    observed: usize,
    signal: Arc<AtomicUsize>,
}

impl SystemBatchWait {
    /// Block until some slot of the closure resolved, then return so the
    /// caller re-runs the whole batch acquisition.
    pub fn wait(&self) {
        loop {
            let current = self.signal.load(Ordering::Acquire);
            if current != self.observed {
                break;
            }
            let _ = atomic_wait(&self.signal, current, Tick::MAX);
        }
    }
}

/// Per-`(domain, soname)` construction state (§13.2).
///
/// `Unloading` hides every member of an SCC while its worker runs fini and
/// releases backing memory. `Initializing`
/// (constructors running) and `Failed` (constructor aborted, no safe rollback)
/// are introduced together with the constructor lifecycle in C27; C24 delivers
/// the permit/lease core and stops at `Relocated`/`Ready`.
enum InstanceState {
    Vacant,
    Loading,
    Relocated,
    /// The batch publication was accepted: the backing, descriptor and fini
    /// plan are registry-owned while the application's constructors run. No
    /// waiter may observe a descriptor here — they stay `Pending` until the
    /// application reports init completion (C31-c, §8.3).
    Initializing {
        descriptor: PublishedImageDescriptor,
        fini_plan: FiniPlan,
        allocation: AllocationLease,
        dependency_names: Vec<DependencyName>,
        dependencies: Vec<SystemDsoLease>,
        scc_members: Vec<DependencyName>,
        keep_cached: bool,
    },
    Ready {
        leases: usize,
        descriptor: PublishedImageDescriptor,
        fini_plan: FiniPlan,
        /// The instance owns its backing (§8.4): the unique allocation lease
        /// and its system-to-system dependency leases live with the Ready
        /// state, released only by the C31-d quiescence worker.
        allocation: AllocationLease,
        dependencies: Vec<SystemDsoLease>,
        scc_members: Vec<DependencyName>,
        keep_cached: bool,
    },
    /// An SCC's backings have moved to a [`SystemUnloadBatch`]. The state is
    /// not re-acquirable until the worker calls `finish_unload`.
    Unloading,
    /// Constructor aborted (thread fault or exit before init completion): no
    /// half-initialized descriptor may be published. The backing is retained
    /// here until the registry worker releases it (C31-d), while the slot
    /// behaves like `Vacant` for a generation+1 retry.
    Failed {
        descriptor: PublishedImageDescriptor,
        fini_plan: FiniPlan,
        allocation: AllocationLease,
        dependency_names: Vec<DependencyName>,
        dependencies: Vec<SystemDsoLease>,
        scc_members: Vec<DependencyName>,
        keep_cached: bool,
    },
}

struct Slot {
    domain: LinkDomainId,
    soname: DependencyName,
    generation: u32,
    state: InstanceState,
    /// Resolution signal: bumped (and its waiters woken) whenever the slot
    /// leaves an in-flight state for a re-acquirable one (`Vacant`
    /// or `Ready`). Waiters key off this atom's stable heap address.
    waiter: Arc<AtomicUsize>,
}

struct Inner {
    slots: Vec<Slot>,
    /// Registry-wide resolution epoch: bumped whenever any slot resolves
    /// (cancel, Ready publication or quiescence decision). Batch waiters key
    /// off it instead of per-slot signals, so a batch covering several slots
    /// re-checks the whole set atomically (C30, §7.3).
    resolution: Arc<AtomicUsize>,
    /// Backings of failed constructor batches, retained until the C31-d
    /// registry worker has quiescence evidence and releases them.
    failed_backings: Vec<AllocationLease>,
}

/// Shared registry handle. `Clone` yields another handle onto the same slot
/// table; each link/thread keeps an independent clone.
pub struct SystemDsoRegistry {
    inner: Arc<Mutex<Inner>>,
}

impl Clone for SystemDsoRegistry {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl SystemDsoRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                slots: Vec::new(),
                resolution: Arc::new(AtomicUsize::new(0)),
                failed_backings: Vec::new(),
            })),
        }
    }

    /// Request `soname` in `domain` (§13.3).
    ///
    /// Vacant → `Permit` (the sole publication authority for a fresh
    /// generation); `Ready` → `Lease` (counter incremented, no re-map);
    /// otherwise → `Pending(current_generation)`.
    pub fn acquire_or_begin_load(
        &self,
        domain: LinkDomainId,
        soname: DependencyName,
    ) -> AcquireOutcome {
        let mut inner = self.inner.lock();
        let index = ensure_slot(&mut inner.slots, domain, soname.clone());
        // A failed constructor batch never publishes a descriptor: the slot
        // re-opens for a generation+1 retry and the failed backing is
        // retained for the C31-d worker (§8.3).
        if matches!(inner.slots[index].state, InstanceState::Failed { .. }) {
            let failed = core::mem::replace(&mut inner.slots[index].state, InstanceState::Vacant);
            if let InstanceState::Failed { allocation, .. } = failed {
                inner.failed_backings.push(allocation);
            }
            let slot = &mut inner.slots[index];
            slot.generation = slot.generation.wrapping_add(1);
            slot.state = InstanceState::Loading;
            return AcquireOutcome::Permit(LoadPermit {
                inner: Arc::clone(&self.inner),
                slot: index,
                generation: slot.generation,
                armed: true,
            });
        }
        let slot = &mut inner.slots[index];
        match &mut slot.state {
            InstanceState::Vacant => {
                slot.generation = slot.generation.wrapping_add(1);
                slot.state = InstanceState::Loading;
                AcquireOutcome::Permit(LoadPermit {
                    inner: Arc::clone(&self.inner),
                    slot: index,
                    generation: slot.generation,
                    armed: true,
                })
            }
            InstanceState::Ready { leases, .. } => {
                *leases = leases.saturating_add(1);
                AcquireOutcome::Lease(SystemDsoLease {
                    inner: Arc::clone(&self.inner),
                    slot: index,
                    generation: slot.generation,
                    domain: slot.domain,
                    soname: slot.soname.clone(),
                })
            }
            InstanceState::Loading
            | InstanceState::Relocated
            | InstanceState::Initializing { .. }
            | InstanceState::Unloading => AcquireOutcome::Pending(WaitHandle {
                generation: slot.generation,
                observed: slot.waiter.load(Ordering::Acquire),
                signal: Arc::clone(&slot.waiter),
            }),
            // Hoisted before the match.
            InstanceState::Failed { .. } => unreachable!("Failed hoisted before the match"),
        }
    }

    /// Atomically acquire the whole declared system closure (C30, §7.3).
    ///
    /// Every slot must be re-acquirable — `Vacant` or `Ready` — in which case
    /// all `Vacant` slots mint a [`LoadPermit`] and all `Ready` slots mint a
    /// [`SystemDsoLease`] plus a descriptor clone, under a single lock hold:
    /// two concurrent sessions can never interleave two half-batches and form
    /// an ABBA cycle. Any in-flight slot leaves the entire set untouched and
    /// returns a [`SystemBatchWait`] ticket; the caller waits outside the lock
    /// and retries the whole batch.
    pub fn acquire_batch(
        &self,
        domain: LinkDomainId,
        sonames: &[DependencyName],
    ) -> AcquireBatchOutcome {
        let mut inner = self.inner.lock();
        // Deterministic order: SONAME byte order, de-duplicated (§7.3).
        let mut ordered: Vec<DependencyName> = sonames.to_vec();
        ordered.sort();
        ordered.dedup();
        for soname in &ordered {
            let index = ensure_slot(&mut inner.slots, domain, soname.clone());
            match inner.slots[index].state {
                InstanceState::Vacant | InstanceState::Ready { .. } => {}
                InstanceState::Failed { .. } => {}
                InstanceState::Loading
                | InstanceState::Relocated
                | InstanceState::Initializing { .. }
                | InstanceState::Unloading => {
                    return AcquireBatchOutcome::Pending(SystemBatchWait {
                        observed: inner.resolution.load(Ordering::Acquire),
                        signal: Arc::clone(&inner.resolution),
                    });
                }
            }
        }
        let mut loads = Vec::new();
        let mut imports = Vec::new();
        for soname in ordered {
            let index = ensure_slot(&mut inner.slots, domain, soname.clone());
            if matches!(inner.slots[index].state, InstanceState::Failed { .. }) {
                // Retryable like `Vacant`: retain the failed backing for the
                // C31-d worker and mint the next generation.
                let failed =
                    core::mem::replace(&mut inner.slots[index].state, InstanceState::Vacant);
                if let InstanceState::Failed { allocation, .. } = failed {
                    inner.failed_backings.push(allocation);
                }
            }
            let slot = &mut inner.slots[index];
            match &mut slot.state {
                InstanceState::Vacant => {
                    slot.generation = slot.generation.wrapping_add(1);
                    slot.state = InstanceState::Loading;
                    loads.push((
                        soname,
                        LoadPermit {
                            inner: Arc::clone(&self.inner),
                            slot: index,
                            generation: slot.generation,
                            armed: true,
                        },
                    ));
                }
                InstanceState::Ready {
                    leases, descriptor, ..
                } => {
                    *leases = leases.saturating_add(1);
                    imports.push((
                        soname,
                        SystemDsoLease {
                            inner: Arc::clone(&self.inner),
                            slot: index,
                            generation: slot.generation,
                            domain: slot.domain,
                            soname: slot.soname.clone(),
                        },
                        descriptor.clone(),
                    ));
                }
                _ => unreachable!("batch pre-check passed"),
            }
        }
        AcquireBatchOutcome::Acquired(PreparedSystemBatch { loads, imports })
    }

    /// Advance a `Loading` slot to `Relocated` once the candidate image's
    /// relocation and seal stage completed (§13.3). All capacity/identity/
    /// generation checks happen in the link publisher's `prepare_batch` before
    /// this call; this only moves the slot and returns the next token.
    pub fn publish_relocated(&self, permit: LoadPermit) -> LoadResult<RelocatedPermit> {
        let (inner, slot, generation) = permit.consume();
        {
            let mut guard = inner.lock();
            let resolution = Arc::clone(&guard.resolution);
            let instance = guard.slots.get_mut(slot).ok_or_else(stale_error)?;
            if instance.generation != generation {
                return Err(stale_error());
            }
            match instance.state {
                InstanceState::Loading => instance.state = InstanceState::Relocated,
                _ => return Err(stale_error()),
            }
            // The slot left an in-flight state for a resolvable one; wake
            // per-slot and registry-wide waiters.
            wake_waiters(&instance.waiter, &resolution);
        }
        Ok(RelocatedPermit {
            inner,
            slot,
            generation,
            armed: true,
        })
    }

    /// Publish a whole batch of relocated system candidates in one lock hold
    /// (C31-c, §8.3): each slot moves `Relocated → Initializing` and the
    /// registry becomes the owner of its backing allocation, descriptor and
    /// fini plan. Waiters stay `Pending` — nothing here publishes a
    /// descriptor. The returned [`SystemInitBatch`] must be advanced with
    /// [`SystemDsoRegistry::finish_initialization_batch`] once the
    /// application reports `ApplicationInitComplete`, or failed through
    /// [`SystemDsoRegistry::fail_initialization_batch`] when the application
    /// dies first.
    pub fn publish_relocated_batch(
        &self,
        permits: Vec<RelocatedPermit>,
        backings: Vec<SystemCandidateBacking>,
    ) -> LoadResult<SystemInitBatch> {
        if permits.len() != backings.len() {
            return Err(stale_error());
        }
        let mut slots = Vec::new();
        let mut generations = Vec::new();
        slots
            .try_reserve(permits.len())
            .map_err(|_| registry_oom())?;
        generations
            .try_reserve(permits.len())
            .map_err(|_| registry_oom())?;
        for (permit, backing) in permits.into_iter().zip(backings.into_iter()) {
            let (inner_arc, slot, generation) = permit.consume();
            {
                let mut guard = inner_arc.lock();
                let instance = guard.slots.get_mut(slot).ok_or_else(stale_error)?;
                if instance.generation != generation {
                    return Err(stale_error());
                }
                match instance.state {
                    InstanceState::Relocated => {
                        instance.state = InstanceState::Initializing {
                            descriptor: backing.descriptor,
                            fini_plan: backing.fini_plan,
                            allocation: backing.allocation,
                            dependency_names: backing.dependency_names,
                            dependencies: backing.dependencies,
                            scc_members: backing.scc_members,
                            keep_cached: backing.keep_cached,
                        };
                    }
                    _ => return Err(stale_error()),
                }
            }
            slots.push(slot);
            generations.push(generation);
        }
        Ok(SystemInitBatch {
            inner: Arc::clone(&self.inner),
            slots,
            generations,
            armed: true,
        })
    }

    /// Complete a published initialization batch: every slot moves
    /// `Initializing → Ready` with one counted lease minted for the
    /// first-loading application group (§8.4 — the first group holds an
    /// ordinary lease like any importer). Called by the
    /// `ApplicationInitComplete` syscall path before the manager marks the
    /// application `Running`; all tokens were validated at publish time, so
    /// this path only moves state.
    pub fn finish_initialization_batch(
        &self,
        batch: SystemInitBatch,
    ) -> LoadResult<Vec<SystemDsoLease>> {
        let (inner, slots, generations) = batch.consume();
        let mut guard = inner.lock();
        let resolution = Arc::clone(&guard.resolution);
        let mut leases = Vec::new();
        leases
            .try_reserve(slots.len())
            .map_err(|_| registry_oom())?;

        // Validate the complete transition and every outgoing dependency
        // before mutating a slot. A provider may be an already-Ready import or
        // another member of this initialization batch.
        for (slot, generation) in slots.iter().zip(generations.iter()) {
            let instance = guard.slots.get(*slot).ok_or_else(stale_error)?;
            if instance.generation != *generation {
                return Err(stale_error());
            }
            let InstanceState::Initializing {
                dependency_names,
                dependencies,
                ..
            } = &instance.state
            else {
                return Err(stale_error());
            };
            if dependencies.capacity() < dependency_names.len() {
                return Err(registry_oom());
            }
            for dependency in dependency_names {
                let provider = guard
                    .slots
                    .iter()
                    .find(|provider| {
                        provider.domain == instance.domain && &provider.soname == dependency
                    })
                    .ok_or_else(stale_error)?;
                match &provider.state {
                    InstanceState::Ready { .. } => {}
                    InstanceState::Initializing { .. } => {
                        let provider_index = guard
                            .slots
                            .iter()
                            .position(|candidate| core::ptr::eq(candidate, provider))
                            .ok_or_else(stale_error)?;
                        if !slots.contains(&provider_index) {
                            return Err(stale_error());
                        }
                    }
                    _ => return Err(stale_error()),
                }
            }
        }

        let mut pending_dependencies = Vec::new();
        pending_dependencies
            .try_reserve(slots.len())
            .map_err(|_| registry_oom())?;
        for (slot, generation) in slots.iter().zip(generations.iter()) {
            let instance = guard.slots.get_mut(*slot).ok_or_else(stale_error)?;
            match core::mem::replace(&mut instance.state, InstanceState::Vacant) {
                InstanceState::Initializing {
                    descriptor,
                    fini_plan,
                    allocation,
                    dependency_names,
                    dependencies,
                    scc_members,
                    keep_cached,
                } => {
                    instance.state = InstanceState::Ready {
                        leases: 1,
                        descriptor,
                        fini_plan,
                        allocation,
                        dependencies,
                        scc_members,
                        keep_cached,
                    };
                    pending_dependencies.push((*slot, dependency_names));
                    leases.push(SystemDsoLease {
                        inner: Arc::clone(&inner),
                        slot: *slot,
                        generation: *generation,
                        domain: instance.domain,
                        soname: instance.soname.clone(),
                    });
                }
                _ => return Err(stale_error()),
            }
        }

        // All candidates are now Ready under the same lock hold. Mint one
        // retained lease for each outgoing cross-SCC edge and attach it to the
        // source instance. Internal SCC edges were removed by the loader.
        for (source_slot, dependency_names) in pending_dependencies {
            for soname in dependency_names {
                let provider_slot = guard
                    .slots
                    .iter()
                    .position(|provider| {
                        provider.domain == guard.slots[source_slot].domain
                            && provider.soname == soname
                    })
                    .ok_or_else(stale_error)?;
                let (domain, generation) = {
                    let provider = &mut guard.slots[provider_slot];
                    let InstanceState::Ready { leases, .. } = &mut provider.state else {
                        return Err(stale_error());
                    };
                    *leases = leases.saturating_add(1);
                    (provider.domain, provider.generation)
                };
                let dependency = SystemDsoLease {
                    inner: Arc::clone(&inner),
                    slot: provider_slot,
                    generation,
                    domain,
                    soname,
                };
                let InstanceState::Ready { dependencies, .. } = &mut guard.slots[source_slot].state
                else {
                    return Err(stale_error());
                };
                dependencies.push(dependency);
            }
        }
        for slot in &slots {
            wake_waiters(&guard.slots[*slot].waiter, &resolution);
        }
        drop(guard);
        Ok(leases)
    }

    /// Fail a published initialization batch: the application died before its
    /// init completed, so no descriptor may be published. Each slot returns to
    /// `Vacant` for a generation+1 retry and its backing is retained for the
    /// C31-d worker; waiters wake and re-acquire (§8.3, §8.6).
    pub fn fail_initialization_batch(&self, batch: SystemInitBatch) {
        let (inner, slots, generations) = batch.consume();
        let mut guard = inner.lock();
        let resolution = Arc::clone(&guard.resolution);
        for (slot, generation) in slots.iter().zip(generations.iter()) {
            let Some(instance) = guard.slots.get_mut(*slot) else {
                continue;
            };
            if instance.generation != *generation {
                continue;
            }
            match core::mem::replace(&mut instance.state, InstanceState::Vacant) {
                InstanceState::Initializing {
                    descriptor,
                    fini_plan,
                    allocation,
                    dependency_names,
                    dependencies,
                    scc_members,
                    keep_cached,
                } => {
                    instance.state = InstanceState::Failed {
                        descriptor,
                        fini_plan,
                        allocation,
                        dependency_names,
                        dependencies,
                        scc_members,
                        keep_cached,
                    };
                }
                _ => {
                    instance.state = InstanceState::Vacant;
                }
            }
            wake_waiters(&instance.waiter, &resolution);
        }
    }

    /// Resolve the zero-user SCC containing `soname` once the reaper has
    /// quiescence evidence (§13.3, C31-d §8.5).
    ///
    /// Every member must be Ready with zero counted leases. If any member is
    /// cache-pinned, the whole SCC stays Ready. Otherwise all members move to
    /// `Unloading` in one lock hold and their backings are handed to the
    /// worker; no concurrent acquire can observe a half-destroyed SCC.
    pub fn resolve_quiescence(
        &self,
        domain: LinkDomainId,
        soname: &DependencyName,
        keep_cached: bool,
    ) -> Option<QuiescenceResolution> {
        let mut inner = self.inner.lock();
        let index = inner
            .slots
            .iter()
            .position(|s| s.domain == domain && &s.soname == soname)?;
        let InstanceState::Ready {
            leases: 0,
            scc_members,
            keep_cached: stored_keep_cached,
            ..
        } = &inner.slots[index].state
        else {
            return None;
        };

        let mut members = Vec::new();
        members.try_reserve(scc_members.len()).ok()?;
        for member in scc_members {
            let member_index = inner
                .slots
                .iter()
                .position(|slot| slot.domain == domain && &slot.soname == member)?;
            if !members.contains(&member_index) {
                members.push(member_index);
            }
        }
        if members.is_empty() {
            members.push(index);
        }

        let mut group_keep_cached = keep_cached || *stored_keep_cached;
        for member in &members {
            let InstanceState::Ready {
                leases: 0,
                keep_cached,
                ..
            } = &inner.slots[*member].state
            else {
                return None;
            };
            group_keep_cached |= *keep_cached;
        }
        if group_keep_cached {
            return Some(QuiescenceResolution::KeptCached);
        }

        let mut backings = Vec::new();
        let mut slots = Vec::new();
        let mut generations = Vec::new();
        backings.try_reserve(members.len()).ok()?;
        slots.try_reserve(members.len()).ok()?;
        generations.try_reserve(members.len()).ok()?;
        for member in members {
            let slot = &mut inner.slots[member];
            let state = core::mem::replace(&mut slot.state, InstanceState::Unloading);
            let InstanceState::Ready {
                leases: 0,
                descriptor: _,
                fini_plan,
                allocation,
                dependencies,
                scc_members: _,
                keep_cached: _,
            } = state
            else {
                unreachable!("SCC quiescence was validated before transition")
            };
            slots.push(member);
            generations.push(slot.generation);
            backings.push(SystemUnloadBacking {
                soname: slot.soname.clone(),
                allocation,
                fini_plan,
                dependencies,
            });
        }
        drop(inner);
        Some(QuiescenceResolution::Unloaded(SystemUnloadBatch {
            inner: Arc::clone(&self.inner),
            slots,
            generations,
            backings,
        }))
    }

    /// Publish completion of a system SCC's fini/release work. Only now do its
    /// slots become `Vacant` and wake waiters for generation+1.
    pub fn finish_unload(&self, mut batch: SystemUnloadBatch) -> LoadResult<()> {
        if !Arc::ptr_eq(&self.inner, &batch.inner) || !batch.backings.is_empty() {
            return Err(stale_error());
        }
        let mut inner = batch.inner.lock();
        let resolution = Arc::clone(&inner.resolution);
        for (slot, generation) in batch.slots.iter().zip(batch.generations.iter()) {
            let instance = inner.slots.get(*slot).ok_or_else(stale_error)?;
            if instance.generation != *generation
                || !matches!(instance.state, InstanceState::Unloading)
            {
                return Err(stale_error());
            }
        }
        for slot in core::mem::take(&mut batch.slots) {
            let instance = &mut inner.slots[slot];
            instance.state = InstanceState::Vacant;
            wake_waiters(&instance.waiter, &resolution);
        }
        Ok(())
    }

    /// Drain the failed constructor batches' retained backings (C31-c, §8.6):
    /// the C31-d worker releases them once it has quiescence evidence.
    pub fn drain_failed_backings(&self) -> Vec<AllocationLease> {
        let mut inner = self.inner.lock();
        core::mem::take(&mut inner.failed_backings)
    }

    /// The current generation of `soname` in `domain`, if any.
    pub fn generation(&self, domain: LinkDomainId, soname: &DependencyName) -> Option<u32> {
        let inner = self.inner.lock();
        inner
            .slots
            .iter()
            .find(|s| s.domain == domain && &s.soname == soname)
            .map(|s| s.generation)
    }

    /// The number of live leases on a Ready instance (0 if not Ready).
    pub fn lease_count(&self, domain: LinkDomainId, soname: &DependencyName) -> Option<usize> {
        let inner = self.inner.lock();
        inner
            .slots
            .iter()
            .find(|s| s.domain == domain && &s.soname == soname)
            .map(|s| match &s.state {
                InstanceState::Ready { leases, .. } => *leases,
                _ => 0,
            })
    }

    /// A clone of the retained descriptor for a Ready instance, for the resolver
    /// to hand back as an [`blueos_loader::ImportedImageDescriptor`] (§12.1).
    pub fn descriptor(
        &self,
        domain: LinkDomainId,
        soname: &DependencyName,
    ) -> Option<PublishedImageDescriptor> {
        let inner = self.inner.lock();
        let slot = inner
            .slots
            .iter()
            .find(|s| s.domain == domain && &s.soname == soname)?;
        match &slot.state {
            InstanceState::Ready { descriptor, .. } => Some(descriptor.clone()),
            _ => None,
        }
    }

    /// A clone of the retained fini plan for a Ready instance, for the reaper.
    pub fn fini_plan(&self, domain: LinkDomainId, soname: &DependencyName) -> Option<FiniPlan> {
        let inner = self.inner.lock();
        let slot = inner
            .slots
            .iter()
            .find(|s| s.domain == domain && &s.soname == soname)?;
        match &slot.state {
            InstanceState::Ready { fini_plan, .. } => Some(fini_plan.clone()),
            _ => None,
        }
    }
}

impl Default for SystemDsoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The unique publication authority for a `Loading` slot (§13.3).
///
/// Exactly one is minted per generation. It must be advanced with
/// [`SystemDsoRegistry::publish_relocated`]; dropping it armed cancels the load.
pub struct LoadPermit {
    inner: Arc<Mutex<Inner>>,
    slot: usize,
    generation: u32,
    armed: bool,
}

impl LoadPermit {
    /// Disarm and hand back the internals, leaving `self` to drop harmlessly.
    fn consume(mut self) -> (Arc<Mutex<Inner>>, usize, u32) {
        self.armed = false;
        (Arc::clone(&self.inner), self.slot, self.generation)
    }
}

impl Drop for LoadPermit {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            let mut guard = self.inner.lock();
            let resolution = Arc::clone(&guard.resolution);
            let Some(slot) = guard.slots.get_mut(self.slot) else {
                return;
            };
            if slot.generation != self.generation || !matches!(slot.state, InstanceState::Loading) {
                return;
            }
            slot.state = InstanceState::Vacant;
            // Cancelling back to `Vacant` makes the slot re-acquirable: wake
            // any waiter blocked on this in-flight generation (§13.5).
            wake_waiters(&slot.waiter, &resolution);
        }
    }
}

/// The publication authority for a `Relocated` slot, returned by
/// [`SystemDsoRegistry::publish_relocated`] (§13.3).
///
/// It must be advanced with [`SystemDsoRegistry::mark_ready`]. Dropping it
/// armed cancels back to `Vacant` — still safe, because no constructor has run.
pub struct RelocatedPermit {
    inner: Arc<Mutex<Inner>>,
    slot: usize,
    generation: u32,
    armed: bool,
}

impl RelocatedPermit {
    fn consume(mut self) -> (Arc<Mutex<Inner>>, usize, u32) {
        self.armed = false;
        (Arc::clone(&self.inner), self.slot, self.generation)
    }
}

impl Drop for RelocatedPermit {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            let mut guard = self.inner.lock();
            let resolution = Arc::clone(&guard.resolution);
            let Some(slot) = guard.slots.get_mut(self.slot) else {
                return;
            };
            if slot.generation != self.generation || !matches!(slot.state, InstanceState::Relocated)
            {
                return;
            }
            slot.state = InstanceState::Vacant;
            wake_waiters(&slot.waiter, &resolution);
        }
    }
}

/// One counted reference to a Ready system DSO (§13.3).
///
/// `Drop` only decrements the instance's lease count. A zero-user instance
/// remains `Ready` and reusable until an application reaper explicitly asks
/// the registry to resolve quiescence. This matters for pre-publication link
/// failures: they have no installed group receipt/reaper, so the last imported
/// lease must not leave the provider permanently stuck in an in-flight state.
/// Unloading remains a reaper decision made with quiescence evidence
/// (§13.3, C27).
pub struct SystemDsoLease {
    inner: Arc<Mutex<Inner>>,
    slot: usize,
    generation: u32,
    domain: LinkDomainId,
    soname: DependencyName,
}

impl SystemDsoLease {
    /// The link domain this lease was minted for, so the reaper can address the
    /// registry's quiescence decision for the right slot (§16.4).
    #[inline]
    pub const fn domain(&self) -> LinkDomainId {
        self.domain
    }

    /// The SONAME this lease was minted for (§16.4).
    #[inline]
    pub fn soname(&self) -> &DependencyName {
        &self.soname
    }
}

impl Drop for SystemDsoLease {
    fn drop(&mut self) {
        let mut guard = self.inner.lock();
        let Some(slot) = guard.slots.get_mut(self.slot) else {
            return;
        };
        if slot.generation != self.generation {
            return;
        }
        let InstanceState::Ready { leases, .. } = &mut slot.state else {
            return;
        };
        *leases = leases.saturating_sub(1);
    }
}

/// A waiter blocked on an in-flight generation (§13.3).
///
/// A resolver that receives [`AcquireOutcome::Pending`] holds this handle and
/// calls [`WaitHandle::wait`] *outside* any loader-memory or manager lock. The
/// handle records both the generation it observed and the resolution-signal
/// epoch current at mint time, so a wake that resolves a *different* generation
/// is still safe: after unblocking, the resolver simply re-requests and observes
/// the current state rather than trusting a stale result.
pub struct WaitHandle {
    generation: u32,
    /// Signal epoch captured while the generation was still in flight. `wait`
    /// blocks until the signal moves past this value.
    observed: usize,
    signal: Arc<AtomicUsize>,
}

impl WaitHandle {
    /// The generation that was mid-construction when this handle was minted.
    #[inline]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Block until the in-flight generation resolves (the slot becomes `Vacant`
    /// or `Ready`), then return so the caller can re-acquire.
    ///
    /// The waiter sleeps while the resolution signal is unchanged and returns
    /// once a [`wake_waiters`] bump moves it past the observed epoch. A spurious
    /// or stale wake only causes a harmless re-check: `atomic_wait` re-validates
    /// under the wait-queue lock, so a bump racing this check is observed as
    /// `EAGAIN` and re-looped rather than lost.
    pub fn wait(&self) {
        loop {
            let current = self.signal.load(Ordering::Acquire);
            if current != self.observed {
                break;
            }
            let _ = atomic_wait(&self.signal, current, Tick::MAX);
        }
    }
}

/// Bump a slot's resolution signal and wake every waiter blocked on it (§13.5).
///
/// The bump happens-before the wake so a waiter that has not yet slept observes
/// the new value via `atomic_wait`'s re-check and returns immediately, while a
/// sleeping waiter is woken and re-checks the same way.
fn registry_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}

fn wake_waiters(signal: &AtomicUsize, resolution: &AtomicUsize) {
    signal.fetch_add(1, Ordering::Release);
    let _ = atomic_wake(signal, usize::MAX);
    // The registry-wide epoch moves too so batch waiters re-check the whole
    // set (§7.3).
    resolution.fetch_add(1, Ordering::Release);
    let _ = atomic_wake(resolution, usize::MAX);
}

fn ensure_slot(slots: &mut Vec<Slot>, domain: LinkDomainId, soname: DependencyName) -> usize {
    if let Some(index) = slots
        .iter()
        .position(|s| s.domain == domain && s.soname == soname)
    {
        return index;
    }
    slots.push(Slot {
        domain,
        soname,
        generation: 0,
        state: InstanceState::Vacant,
        waiter: Arc::new(AtomicUsize::new(0)),
    });
    slots.len() - 1
}

fn stale_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;

    fn name(bytes: &[u8]) -> DependencyName {
        DependencyName::from_terminated(bytes).expect("valid soname")
    }

    #[test]
    fn vacant_slot_grants_a_single_permit_then_pends() {
        let registry = SystemDsoRegistry::new();
        let domain = LinkDomainId::new(7);
        let soname = name(b"libc.so.1\0");

        let first = registry.acquire_or_begin_load(domain, soname.clone());
        assert!(matches!(first, AcquireOutcome::Permit(_)));
        // A second request while Loading must not mint a second permit.
        let AcquireOutcome::Pending(handle) =
            registry.acquire_or_begin_load(domain, soname.clone())
        else {
            panic!("expected pending");
        };
        assert_eq!(handle.generation(), 1);
        // The permit is the sole publication authority for generation 1.
        assert_eq!(registry.generation(domain, &soname), Some(1));
    }

    #[test]
    fn dropping_an_armed_permit_returns_to_vacant() {
        let registry = SystemDsoRegistry::new();
        let domain = LinkDomainId::new(7);
        let soname = name(b"libc.so.1\0");

        let AcquireOutcome::Permit(permit) = registry.acquire_or_begin_load(domain, soname.clone())
        else {
            panic!("expected permit");
        };
        drop(permit);
        // Cancelled: the next request wins a fresh (bumped) generation.
        assert!(matches!(
            registry.acquire_or_begin_load(domain, soname.clone()),
            AcquireOutcome::Permit(_)
        ));
        assert_eq!(registry.generation(domain, &soname), Some(2));
    }

    #[test]
    fn dropping_an_armed_relocated_permit_cancels_too() {
        let registry = SystemDsoRegistry::new();
        let domain = LinkDomainId::new(7);
        let soname = name(b"libc.so.1\0");

        let AcquireOutcome::Permit(permit) = registry.acquire_or_begin_load(domain, soname.clone())
        else {
            panic!("expected permit");
        };
        let relocated = registry.publish_relocated(permit).expect("relocate");
        drop(relocated);
        // Nothing ran: a later request wins a fresh generation.
        assert!(matches!(
            registry.acquire_or_begin_load(domain, soname.clone()),
            AcquireOutcome::Permit(_)
        ));
        assert_eq!(registry.generation(domain, &soname), Some(2));
    }

    #[test]
    fn pending_tracks_the_inflight_generation() {
        let registry = SystemDsoRegistry::new();
        let domain = LinkDomainId::new(7);
        let soname = name(b"libc.so.1\0");

        // Hold the permit so the slot stays Loading across the second request.
        let _permit = registry.acquire_or_begin_load(domain, soname.clone());
        let AcquireOutcome::Pending(handle) =
            registry.acquire_or_begin_load(domain, soname.clone())
        else {
            panic!("expected pending");
        };
        assert_eq!(handle.generation(), 1);
    }

    // §13.5: a permit owner that drops before publication must wake the waiter
    // blocked on that generation. Single-threaded here, so we resolve first and
    // then observe `wait` return immediately (the signal has already advanced
    // past the epoch the handle observed); the sleeping path is covered by the
    // multi-threaded QEMU integration fixtures.
    #[test]
    fn dropping_a_permit_wakes_a_waiting_resolver() {
        let registry = SystemDsoRegistry::new();
        let domain = LinkDomainId::new(7);
        let soname = name(b"libc.so.1\0");

        let AcquireOutcome::Permit(permit) = registry.acquire_or_begin_load(domain, soname.clone())
        else {
            panic!("expected permit");
        };
        let AcquireOutcome::Pending(handle) =
            registry.acquire_or_begin_load(domain, soname.clone())
        else {
            panic!("expected pending");
        };
        drop(permit);
        // Must not deadlock: the permit's cancellation bumped the signal.
        handle.wait();
        // The waiter can now re-acquire on the fresh generation.
        assert!(matches!(
            registry.acquire_or_begin_load(domain, soname.clone()),
            AcquireOutcome::Permit(_)
        ));
    }
}
