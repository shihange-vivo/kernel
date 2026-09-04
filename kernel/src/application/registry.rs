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
//!   the counter and, when the last lease goes, moves the slot to `Quiescing`:
//!   it never executes application code and never releases the image (§13.3).
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

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use blueos_loader::{
    DependencyName, ErrorContext, FiniPlan, LinkDomainId, LoadError, LoadErrorKind, LoadResult,
    PublishedImageDescriptor,
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

/// Per-`(domain, soname)` construction state (§13.2).
///
/// `Quiescing` retains the descriptor and fini plan of the instance whose last
/// lease dropped, so `resolve_quiescence` can either keep it cached (back to a
/// zero-lease `Ready`) or unload it (back to `Vacant`). `Initializing`
/// (constructors running) and `Failed` (constructor aborted, no safe rollback)
/// are introduced together with the constructor lifecycle in C27; C24 delivers
/// the permit/lease core and stops at `Relocated`/`Ready`.
enum InstanceState {
    Vacant,
    Loading,
    Relocated,
    Ready {
        leases: usize,
        descriptor: PublishedImageDescriptor,
        fini_plan: FiniPlan,
    },
    Quiescing {
        descriptor: PublishedImageDescriptor,
        fini_plan: FiniPlan,
    },
}

struct Slot {
    domain: LinkDomainId,
    soname: DependencyName,
    generation: u32,
    state: InstanceState,
    /// Resolution signal: bumped (and its waiters woken) whenever the slot
    /// leaves an in-flight or quiescing state for a re-acquirable one (`Vacant`
    /// or `Ready`). Waiters key off this atom's stable heap address.
    waiter: Arc<AtomicUsize>,
}

struct Inner {
    slots: Vec<Slot>,
}

/// Shared registry handle. `Clone` yields another handle onto the same slot
/// table; each link/thread keeps an independent clone.
pub struct SystemDsoRegistry {
    inner: Arc<Mutex<Inner>>,
}

impl SystemDsoRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner { slots: Vec::new() })),
        }
    }

    /// A handle onto the same slot table, for a resolver or reaper running on a
    /// different thread than the one that created the registry (§14.2).
    #[inline]
    pub fn clone_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
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
                })
            }
            InstanceState::Loading
            | InstanceState::Relocated
            | InstanceState::Quiescing { .. } => AcquireOutcome::Pending(WaitHandle {
                generation: slot.generation,
                observed: slot.waiter.load(Ordering::Acquire),
                signal: Arc::clone(&slot.waiter),
            }),
        }
    }

    /// Advance a `Loading` slot to `Relocated` once the candidate image's
    /// relocation and seal stage completed (§13.3). All capacity/identity/
    /// generation checks happen in the link publisher's `prepare_batch` before
    /// this call; this only moves the slot and returns the next token.
    pub fn publish_relocated(&self, permit: LoadPermit) -> LoadResult<RelocatedPermit> {
        let (inner, slot, generation) = permit.consume();
        {
            let mut guard = inner.lock();
            let instance = guard.slots.get_mut(slot).ok_or_else(stale_error)?;
            if instance.generation != generation {
                return Err(stale_error());
            }
            match instance.state {
                InstanceState::Loading => instance.state = InstanceState::Relocated,
                _ => return Err(stale_error()),
            }
        }
        Ok(RelocatedPermit {
            inner,
            slot,
            generation,
            armed: true,
        })
    }

    /// Publish a fully relocated and sealed image as the Ready instance for its
    /// generation (§13.3). `descriptor`/`fini_plan` are the values the link
    /// publisher's receipt carries (C26); the registry retains them so a later
    /// link can import this instance and the reaper can run its destructors.
    pub fn mark_ready(
        &self,
        relocated: RelocatedPermit,
        descriptor: PublishedImageDescriptor,
        fini_plan: FiniPlan,
    ) -> LoadResult<u32> {
        let (inner, slot, generation) = relocated.consume();
        let signal = {
            let mut guard = inner.lock();
            let instance = guard.slots.get_mut(slot).ok_or_else(stale_error)?;
            if instance.generation != generation {
                return Err(stale_error());
            }
            match instance.state {
                InstanceState::Relocated => {
                    instance.state = InstanceState::Ready {
                        leases: 0,
                        descriptor,
                        fini_plan,
                    };
                    Arc::clone(&instance.waiter)
                }
                _ => return Err(stale_error()),
            }
        };
        wake_waiters(&signal);
        Ok(generation)
    }

    /// Resolve a `Quiescing` slot once the reaper has evidence it is safe to
    /// either keep cached (no unload) or unload and allow `generation + 1` to
    /// reload (§13.3). Returns the resulting generation, or `None` if the slot
    /// was not `Quiescing`.
    pub fn resolve_quiescence(
        &self,
        domain: LinkDomainId,
        soname: &DependencyName,
        keep_cached: bool,
    ) -> Option<u32> {
        let resolved = {
            let mut inner = self.inner.lock();
            let index = inner
                .slots
                .iter()
                .position(|s| s.domain == domain && &s.soname == soname)?;
            let slot = &mut inner.slots[index];
            let state = core::mem::replace(&mut slot.state, InstanceState::Vacant);
            match state {
                InstanceState::Quiescing { descriptor, fini_plan } => {
                    if keep_cached {
                        // KeepCached: stay Ready with zero leases so a later import
                        // takes the fast path without a reload (§13.3).
                        slot.state = InstanceState::Ready {
                            leases: 0,
                            descriptor,
                            fini_plan,
                        };
                    }
                    // Otherwise the pre-replace `Vacant` is already correct.
                    Some((slot.generation, Arc::clone(&slot.waiter)))
                }
                other => {
                    slot.state = other;
                    None
                }
            }
        };
        match resolved {
            Some((generation, signal)) => {
                wake_waiters(&signal);
                Some(generation)
            }
            None => None,
        }
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
        let signal = {
            let mut guard = self.inner.lock();
            let Some(slot) = guard.slots.get_mut(self.slot) else {
                return;
            };
            if slot.generation != self.generation || !matches!(slot.state, InstanceState::Loading) {
                return;
            }
            slot.state = InstanceState::Vacant;
            Arc::clone(&slot.waiter)
        };
        // Cancelling back to `Vacant` makes the slot re-acquirable: wake any
        // waiter blocked on this in-flight generation (§13.5).
        wake_waiters(&signal);
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
        let signal = {
            let mut guard = self.inner.lock();
            let Some(slot) = guard.slots.get_mut(self.slot) else {
                return;
            };
            if slot.generation != self.generation
                || !matches!(slot.state, InstanceState::Relocated)
            {
                return;
            }
            slot.state = InstanceState::Vacant;
            Arc::clone(&slot.waiter)
        };
        wake_waiters(&signal);
    }
}

/// One counted reference to a Ready system DSO (§13.3).
///
/// `Drop` only decrements the instance's lease count and, when the last lease
/// goes, moves the slot to `Quiescing` (retaining the descriptor and fini plan
/// for the reaper's decision). It never runs application code and never
/// releases the mapped image: unloading is the reaper's decision, made with
/// quiescence evidence (§13.3, C27).
pub struct SystemDsoLease {
    inner: Arc<Mutex<Inner>>,
    slot: usize,
    generation: u32,
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
        if *leases == 0 {
            let state = core::mem::replace(&mut slot.state, InstanceState::Vacant);
            if let InstanceState::Ready {
                descriptor,
                fini_plan,
                ..
            } = state
            {
                slot.state = InstanceState::Quiescing {
                    descriptor,
                    fini_plan,
                };
            }
        }
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
fn wake_waiters(signal: &AtomicUsize) {
    signal.fetch_add(1, Ordering::Release);
    let _ = atomic_wake(signal, usize::MAX);
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

        let AcquireOutcome::Permit(permit) =
            registry.acquire_or_begin_load(domain, soname.clone())
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

        let AcquireOutcome::Permit(permit) =
            registry.acquire_or_begin_load(domain, soname.clone())
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

        let AcquireOutcome::Permit(permit) =
            registry.acquire_or_begin_load(domain, soname.clone())
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
