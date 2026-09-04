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

//! The thread-group backend and per-application thread group (C25, §14.1).
//!
//! A [`ThreadGroup`] is the per-application container the manager mints at
//! launch before any thread runs (§14.2 step 3). C26 installs a link product
//! into it (replacing [`GroupState::New`] with `Linked`), and C27 attaches
//! member threads and drives the two-phase exit. C25 delivers the container and
//! its backend: the shape later slices populate, not the membership or reaping
//! logic.
//!
//! A group is a cloneable handle onto an `Arc<Mutex<_>>`, so C26/C27 reach the
//! same membership set from the manager's slot table without holding the
//! manager's lock.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::Mutex;

use blueos_loader::LinkProduct;

use crate::{
    application::{
        event_queue::{ApplicationEvent, ApplicationEventQueue},
        publication::KernelLinkReceipt,
    },
    thread::{Thread, ThreadNode},
};

/// The lifecycle of a thread group's internal state (§6.3).
///
/// This is the execution backend's internal state, distinct from the public
/// [`crate::application::manager::ApplicationState`]: the backend tracks the
/// link install and the two-phase exit, while the public state tracks the
/// application's `Loading → Running → Stopping → Terminated/Failed` lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupState {
    /// Created, no threads running, no link product installed (§14.2 step 3).
    New,
    /// A link product is installed (C26); threads may join and the entry is
    /// publishable.
    Linked,
    /// `ApplicationBeginExit` has run: no new threads may join, and the exit
    /// coordinator is waiting for members to leave before reaping (§16.1).
    Draining,
    /// The reaper took the group's resources; no further lifecycle calls are
    /// valid (§16.4).
    Reaped,
}

/// Whether the application's destructors ran before reaping (§16.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitFini {
    /// Not yet run and not yet skipped.
    Pending,
    /// Normal path: the exit coordinator ran the fini plan and completed.
    Complete,
    /// Abnormal path: the coordinator recorded `SkipFini` and destructors will
    /// not run.
    Skipped,
}

/// Errors the group reports without panicking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadGroupError {
    AlreadyMember,
    NotMember,
    AlreadyLinked,
    /// `add_member` while the group is draining or reaped (§16.1).
    Draining,
    /// `add_member` could not reserve the member's exit-event slot (§16.3).
    EventReservationFailed,
    /// `begin_exit` on a group that has not installed a link product.
    NotLinked,
    /// A duplicate `begin_exit` on a group already draining (§16.5).
    AlreadyDraining,
    /// A lifecycle call that requires a draining group was made too early.
    NotDraining,
    /// `take_resources_for_reap` before fini completed or was skipped (§16.4).
    FiniPending,
    /// `take_resources_for_reap` while member threads remain (§16.4).
    MembersRemaining,
    /// The group's resources were already taken (§16.4).
    AlreadyReaped,
}

struct GroupInner {
    state: GroupState,
    members: Vec<ThreadNode>,
    /// The committed link product (C26). Owned here so its `KernelLinkReceipt`
    /// keeps every private/system allocation lease alive until the C27 reaper
    /// takes them; `None` while the group is [`GroupState::New`] or after the
    /// reaper moved it out.
    product: Option<LinkProduct<KernelLinkReceipt>>,
    /// The fini-plan disposition, set only once draining begins (§16.4).
    fini: ExitFini,
    /// The bounded, capacity-guaranteed exit-event queue the scheduler's
    /// context-switch cleanup delivers into (§16.3). One slot per member is
    /// reserved up front, so the cleanup path never allocates.
    events: ApplicationEventQueue,
}

/// A per-application thread group. `Clone` yields another handle onto the same
/// membership set.
pub struct ThreadGroup {
    inner: Arc<Mutex<GroupInner>>,
}

impl Clone for ThreadGroup {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// A thread's membership in an application thread group (C27, §16.1).
///
/// Held by every thread that runs inside a dynamic application; a static kernel
/// thread carries `None` instead. `Clone` yields another weak handle onto the
/// same [`ThreadGroup`], so a `pthread` created while running inside an
/// application inherits the creator's membership and joins the same group.
///
/// The handle is *weak* by design: the group holds a strong [`ThreadNode`] for
/// every member, so a strong membership back-reference would form a reference
/// cycle and leak the whole group (§16.1 "group 在 Draining 后拒绝创建新线程").
/// [`ThreadGroupMembership::upgrade`] re-acquires the group while it is still
/// live; once the last strong reference (the manager slot + live members) drops,
/// the group is reclaimed and `upgrade` returns `None`.
///
/// The `Debug` impl prints only a marker: the wrapped group owns a live link
/// product and member list that must never be formatted under a derived `Debug`
/// reachable from the scheduler's interrupt context.
#[derive(Clone)]
pub struct ThreadGroupMembership {
    inner: Weak<Mutex<GroupInner>>,
}

impl ThreadGroupMembership {
    /// A weak handle onto `group`, minted by the group's owner when a thread
    /// joins it.
    pub fn downgrade(group: &ThreadGroup) -> Self {
        Self {
            inner: Arc::downgrade(&group.inner),
        }
    }

    /// Re-acquire the group if it is still live. Returns `None` once the last
    /// strong reference has dropped and the group has been reclaimed.
    pub fn upgrade(&self) -> Option<ThreadGroup> {
        self.inner.upgrade().map(|inner| ThreadGroup { inner })
    }
}

impl core::fmt::Debug for ThreadGroupMembership {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ThreadGroupMembership { .. }")
    }
}

impl ThreadGroup {
    fn with_state(state: GroupState) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GroupInner {
                state,
                members: Vec::new(),
                product: None,
                fini: ExitFini::Pending,
                events: ApplicationEventQueue::default(),
            })),
        }
    }

    /// The group's current state.
    pub fn state(&self) -> GroupState {
        self.inner.lock().state
    }

    /// Install a committed link product, moving the group from `New` to
    /// `Linked` (§15.2).
    ///
    /// This is the infallible second half of the two-phase install: the
    /// `KernelLinkPublisher::prepare_batch` check already proved the group was
    /// unlinked, and this move only swaps the fully-built product into place.
    /// A reader therefore observes either the old `New` state or a complete
    /// product, never a half-written link map.
    pub fn install_link_product(
        &self,
        product: LinkProduct<KernelLinkReceipt>,
    ) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        if inner.state != GroupState::New {
            return Err(ThreadGroupError::AlreadyLinked);
        }
        inner.state = GroupState::Linked;
        inner.product = Some(product);
        Ok(())
    }

    /// Record `thread` as a member of this group. A thread may join a group at
    /// most once; a duplicate id is rejected so membership stays countable for
    /// the C27 reaper. Once the group is draining (or reaped) it rejects new
    /// members, so the membership set can only shrink after `begin_exit` (§16.1).
    pub fn add_member(&self, thread: ThreadNode) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        match inner.state {
            GroupState::Draining | GroupState::Reaped => return Err(ThreadGroupError::Draining),
            _ => {}
        }
        let id = Thread::id(&thread);
        if inner
            .members
            .iter()
            .any(|member| Thread::id(member) == id)
        {
            return Err(ThreadGroupError::AlreadyMember);
        }
        // Reserve the exit-event slot before counting the member, so the
        // scheduler's cleanup path always has capacity to record this thread's
        // exit (§16.3). On allocation failure the member is rejected rather than
        // admitted without a slot — the alternative would risk dropping its
        // last-exit notification under OOM.
        if !inner.events.reserve_capacity(1) {
            return Err(ThreadGroupError::EventReservationFailed);
        }
        inner.members.push(thread);
        Ok(())
    }

    /// Remove the member identified by thread id, for the C27 reaper's exit
    /// path.
    pub fn remove_member(&self, id: usize) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        let index = inner
            .members
            .iter()
            .position(|member| Thread::id(member) == id)
            .ok_or(ThreadGroupError::NotMember)?;
        inner.members.swap_remove(index);
        Ok(())
    }

    /// Retire a member from the coordinator side: remove it from the membership
    /// set and enqueue an [`ApplicationEvent::ExecutionUnitExited`] into the
    /// group's exit-event queue (§16.3).
    ///
    /// This is the coordinator's counterpart to the scheduler's lock-free post
    /// into [`ThreadGroup::events`]: the coordinator drains posted exits under
    /// the group lock, retiring the member so [`ThreadGroup::take_resources_for_reap`]
    /// can observe an empty membership set. The enqueue never allocates —
    /// capacity was reserved by [`ThreadGroup::add_member`] — so it can only
    /// fail if a member was admitted without a slot (a programming error).
    pub fn record_member_exit(&self, id: usize) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        let index = inner
            .members
            .iter()
            .position(|member| Thread::id(member) == id)
            .ok_or(ThreadGroupError::NotMember)?;
        inner.members.swap_remove(index);
        let evicted = inner.events.enqueue_or_oldest(ApplicationEvent::ExecutionUnitExited {
            thread_id: id,
        });
        debug_assert!(evicted.is_none(), "exit-event slot was not reserved");
        Ok(())
    }

    /// A cloneable handle onto the group's exit-event queue, for the exit
    /// coordinator to drain member exits (§16.3).
    pub fn events(&self) -> ApplicationEventQueue {
        self.inner.lock().events.clone()
    }

    /// The number of live member threads.
    pub fn member_count(&self) -> usize {
        self.inner.lock().members.len()
    }

    /// Whether the group has no live members (§16.5 quiescence precondition).
    pub fn is_empty(&self) -> bool {
        self.member_count() == 0
    }

    /// Begin the two-phase exit: atomically forbid new threads and move the
    /// group from `Linked` to `Draining` (§16.2). Only the exit coordinator for
    /// this group may call it; a duplicate or out-of-order call is rejected.
    pub fn begin_exit(&self) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        match inner.state {
            GroupState::Linked => {
                inner.state = GroupState::Draining;
                Ok(())
            }
            GroupState::Draining => Err(ThreadGroupError::AlreadyDraining),
            GroupState::New => Err(ThreadGroupError::NotLinked),
            GroupState::Reaped => Err(ThreadGroupError::AlreadyReaped),
        }
    }

    /// Record that the normal-path destructor plan completed (§16.4). Must be
    /// called exactly once, while draining.
    pub fn finish_fini(&self) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        if inner.state != GroupState::Draining {
            return Err(ThreadGroupError::NotDraining);
        }
        if inner.fini != ExitFini::Pending {
            return Err(ThreadGroupError::AlreadyReaped);
        }
        inner.fini = ExitFini::Complete;
        Ok(())
    }

    /// Record that the destructors are intentionally skipped with a recorded
    /// reason (abnormal path, §16.4). Must be called exactly once, while
    /// draining, and only before a normal `finish_fini`.
    pub fn skip_fini(&self) -> Result<(), ThreadGroupError> {
        let mut inner = self.inner.lock();
        if inner.state != GroupState::Draining {
            return Err(ThreadGroupError::NotDraining);
        }
        if inner.fini != ExitFini::Pending {
            return Err(ThreadGroupError::AlreadyReaped);
        }
        inner.fini = ExitFini::Skipped;
        Ok(())
    }

    /// Take the group's committed link product for reaping, exactly once
    /// (§16.4). Succeeds only when new threads are forbidden (`Draining`), no
    /// member threads remain, and the fini disposition is resolved (complete or
    /// skipped). The returned product owns every allocation lease the reaper
    /// must release; the group moves to `Reaped` and no further lifecycle calls
    /// are valid.
    pub fn take_resources_for_reap(
        &self,
    ) -> Result<LinkProduct<KernelLinkReceipt>, ThreadGroupError> {
        let mut inner = self.inner.lock();
        if inner.state != GroupState::Draining {
            return Err(match inner.state {
                GroupState::Reaped => ThreadGroupError::AlreadyReaped,
                GroupState::New => ThreadGroupError::NotLinked,
                GroupState::Linked => ThreadGroupError::NotDraining,
                GroupState::Draining => unreachable!(),
            });
        }
        if !inner.members.is_empty() {
            return Err(ThreadGroupError::MembersRemaining);
        }
        if inner.fini == ExitFini::Pending {
            return Err(ThreadGroupError::FiniPending);
        }
        let product = inner
            .product
            .take()
            .ok_or(ThreadGroupError::AlreadyReaped)?;
        inner.state = GroupState::Reaped;
        Ok(product)
    }
}

/// The backend that mints fresh, not-yet-running thread groups (§14.1).
///
/// The manager owns one backend; `create_group` produces a `New` group with no
/// members. There is no global group table: the manager records each created
/// group in its application slot.
#[derive(Default)]
pub struct ThreadGroupBackend;

impl ThreadGroupBackend {
    pub fn new() -> Self {
        Self
    }

    /// Mint a fresh group with no running threads (§14.2 step 3).
    pub fn create_group(&self) -> ThreadGroup {
        ThreadGroup::with_state(GroupState::New)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::{Builder, Entry, Thread};
    use blueos_test_macro::test;

    fn dummy_thread() -> ThreadNode {
        Builder::new(Entry::C(unreachable_entry)).build()
    }

    extern "C" fn unreachable_entry() {
        unreachable!("never scheduled")
    }

    #[test]
    fn a_fresh_group_has_no_members() {
        let backend = ThreadGroupBackend::new();
        let group = backend.create_group();
        assert_eq!(group.state(), GroupState::New);
        assert!(group.is_empty());
    }

    #[test]
    fn membership_is_counted_and_deduplicated() {
        let backend = ThreadGroupBackend::new();
        let group = backend.create_group();

        let thread = dummy_thread();
        let id = Thread::id(&thread);
        group.add_member(thread.clone()).unwrap();
        assert_eq!(group.member_count(), 1);
        assert!(!group.is_empty());

        // Duplicate id is rejected, not double-counted.
        assert!(matches!(
            group.add_member(thread),
            Err(ThreadGroupError::AlreadyMember)
        ));
        assert_eq!(group.member_count(), 1);

        group.remove_member(id).unwrap();
        assert!(group.is_empty());
    }
}
