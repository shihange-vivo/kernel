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

//! Single application manager: slot table, generation-ABA handles and the
//! explicit state machine (C25, §14).
//!
//! One [`ApplicationManager`] is the only entry through which an application is
//! launched — external syscalls and boot bootstrap both go through
//! [`ApplicationManager::launch`] with an [`OwnedLaunchRequest`]; there is no
//! "boot fast path" that calls a loader directly (§14.2). The manager owns a
//! slot table keyed by request identity; each slot carries a monotonic
//! `generation` so a forged or stale [`ApplicationHandle`] is rejected (§14.3).
//!
//! Phase 1 recognises [`ExecutionModel::Process`] but never enables it: without
//! the `blueos_user_process` configuration the request is rejected with
//! [`ApplicationLaunchError::UnsupportedExecutionModel`] (§14.1). The slow
//! prepare/link step runs *outside* the short table lock; only slot reservation,
//! queries and state transitions take the lock (§14.2, §14.3).
//!
//! [`ApplicationManager::release`] is the recycle primitive the C27 reaper
//! drives after quiescence: it returns a finished slot to `Vacant` so a later
//! launch of the same identity reuses it with a bumped generation. C25 exposes
//! it so slot reuse and generation ABA are observable before the full deferred
//! reaper lands.

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::application::group::{ThreadGroup, ThreadGroupBackend};

/// How an application executes (§14.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionModel {
    /// A thread group inside the shared privileged address space.
    ThreadGroup = 1,
    /// A real process (needs `blueos_user_process`); never enabled in Phase 1.
    Process = 2,
}

/// The lifecycle states of a live application (§14.1).
///
/// The slot-level "no application" state is [`SlotState::Vacant`], which is not
/// an `ApplicationState`: it means the slot is free for reuse, not that an
/// application is in some phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationState {
    Loading,
    Running,
    Stopping,
    Terminated,
    Failed,
}

/// A launch/query handle: slot index plus the generation that slot had when the
/// handle was minted. Generation makes a stale handle fail after the slot is
/// recycled (§14.3 ABA protection).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationHandle {
    pub slot: u32,
    pub generation: u32,
}

/// A copy of an application's observable status (§14.3: queries return copies,
/// never interior `Arc`s, leases or writable state).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationSnapshot {
    pub handle: ApplicationHandle,
    pub state: ApplicationState,
    pub model: ExecutionModel,
}

/// Errors the manager reports without panicking (§14.2 step 10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationLaunchError {
    UnsupportedExecutionModel(ExecutionModel),
    PrepareFailed,
    StaleGeneration,
    AlreadyReleased,
    InvalidTransition {
        from: ApplicationState,
        to: ApplicationState,
    },
}

/// An owned launch request (§14.2). Manifest/ABI-note/profile/quota validation
/// inputs land here together with the C26 linker glue; C25 reserves the slot and
/// validates the execution model only.
pub struct OwnedLaunchRequest {
    model: ExecutionModel,
    identity: Vec<u8>,
}

impl OwnedLaunchRequest {
    pub fn new(model: ExecutionModel, identity: Vec<u8>) -> Self {
        Self { model, identity }
    }

    #[inline]
    pub const fn model(&self) -> ExecutionModel {
        self.model
    }

    #[inline]
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
}

/// Per-`(identity)` construction slot (§14.2, §14.3).
enum SlotState {
    /// Free for reuse. A vacant slot has no live application.
    Vacant,
    Occupied(ApplicationState),
}

struct Slot {
    identity: Vec<u8>,
    model: ExecutionModel,
    generation: u32,
    state: SlotState,
    group: ThreadGroup,
}

impl Slot {
    /// Explicit `expected → next` transition; an illegal transition returns the
    /// error instead of silently crossing states (§14.3).
    fn transition(
        &mut self,
        from: ApplicationState,
        to: ApplicationState,
    ) -> Result<(), ApplicationLaunchError> {
        if !matches!(self.state, SlotState::Occupied(state) if state == from) {
            return Err(ApplicationLaunchError::InvalidTransition {
                from: occupied_state(&self.state),
                to,
            });
        }
        self.state = SlotState::Occupied(to);
        Ok(())
    }
}

struct Inner {
    slots: Vec<Slot>,
}

/// Shared manager handle. `Clone` yields another handle onto the same slot
/// table; each thread keeps an independent clone.
pub struct ApplicationManager {
    inner: Arc<Mutex<Inner>>,
    thread_groups: ThreadGroupBackend,
}

impl ApplicationManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner { slots: Vec::new() })),
            thread_groups: ThreadGroupBackend::new(),
        }
    }

    /// Launch an application (§14.2).
    ///
    /// The slot is reserved (→ `Loading`) and a fresh not-yet-running
    /// [`ThreadGroup`] is minted under the short table lock; the caller's
    /// `prepare` then runs *outside* the lock (slow VFS/link/cache/thread start
    /// must not block other queries or launches), receiving the group so C26 can
    /// install the link product and C27 can create the main thread. On success
    /// the slot transitions to `Running`; on `prepare` failure it is left
    /// queryable as `Failed`. `Process` requests are rejected up front and
    /// reserve nothing.
    pub fn launch<F>(
        &self,
        request: OwnedLaunchRequest,
        prepare: F,
    ) -> Result<ApplicationHandle, ApplicationLaunchError>
    where
        F: FnOnce(&ThreadGroup) -> Result<(), ApplicationLaunchError>,
    {
        if request.model == ExecutionModel::Process {
            return Err(ApplicationLaunchError::UnsupportedExecutionModel(
                request.model,
            ));
        }
        let group = self.thread_groups.create_group();
        let prepare_group = group.clone();
        let (slot, generation) = {
            let mut inner = self.inner.lock();
            reserve_slot(&mut inner.slots, request.identity, request.model, group)
        };

        let result = prepare(&prepare_group);

        let mut inner = self.inner.lock();
        let instance = inner
            .slots
            .get_mut(slot)
            .expect("a reserved slot stays present");
        if instance.generation != generation {
            return Err(ApplicationLaunchError::StaleGeneration);
        }
        match result {
            Ok(()) => {
                instance
                    .transition(ApplicationState::Loading, ApplicationState::Running)?;
                Ok(ApplicationHandle {
                    slot: slot as u32,
                    generation,
                })
            }
            Err(error) => {
                instance.state = SlotState::Occupied(ApplicationState::Failed);
                Err(error)
            }
        }
    }

    /// The thread group of a live application, for C26/C27.
    ///
    /// Unlike the snapshot query, this returns the shared handle (the one C26
    /// installs into and C27 attaches threads to); it is an `Arc<Mutex<_>>` clone,
    /// not the manager's lock-held slot.
    pub fn group(&self, handle: ApplicationHandle) -> Option<ThreadGroup> {
        let inner = self.inner.lock();
        let slot = inner.slots.get(handle.slot as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        match slot.state {
            SlotState::Vacant => None,
            SlotState::Occupied(_) => Some(slot.group.clone()),
        }
    }

    /// Query a live application by handle. Returns `None` for an out-of-range,
    /// stale-generation or already-released slot (§14.3).
    pub fn query(&self, handle: ApplicationHandle) -> Option<ApplicationSnapshot> {
        let inner = self.inner.lock();
        let slot = inner.slots.get(handle.slot as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        match slot.state {
            SlotState::Vacant => None,
            SlotState::Occupied(state) => Some(ApplicationSnapshot {
                handle,
                state,
                model: slot.model,
            }),
        }
    }

    /// Query a live application by request identity, for the case where `launch`
    /// reported an error but left a queryable `Failed` slot (§14.4).
    pub fn query_by_identity(&self, identity: &[u8]) -> Option<ApplicationSnapshot> {
        let inner = self.inner.lock();
        let (index, slot) = inner
            .slots
            .iter()
            .enumerate()
            .find(|(_, s)| matches!(s.state, SlotState::Occupied(_)) && s.identity == identity)?;
        let SlotState::Occupied(state) = slot.state else {
            return None;
        };
        Some(ApplicationSnapshot {
            handle: ApplicationHandle {
                slot: index as u32,
                generation: slot.generation,
            },
            state,
            model: slot.model,
        })
    }

    /// Return a finished application's slot to `Vacant` so a later launch of the
    /// same identity reuses it with a bumped generation (§14.3 ABA). C25 exposes
    /// this recycle primitive directly; the C27 reaper will gate it behind the
    /// two-phase exit (`Running → Stopping → Terminated`) and quiescence
    /// evidence before recycling (§14.4).
    pub fn release(&self, handle: ApplicationHandle) -> Result<(), ApplicationLaunchError> {
        let mut inner = self.inner.lock();
        let slot = inner
            .slots
            .get_mut(handle.slot as usize)
            .ok_or(ApplicationLaunchError::StaleGeneration)?;
        if slot.generation != handle.generation {
            return Err(ApplicationLaunchError::StaleGeneration);
        }
        match slot.state {
            SlotState::Vacant => Err(ApplicationLaunchError::AlreadyReleased),
            SlotState::Occupied(_) => {
                slot.state = SlotState::Vacant;
                Ok(())
            }
        }
    }
}

impl Default for ApplicationManager {
    fn default() -> Self {
        Self::new()
    }
}

fn occupied_state(state: &SlotState) -> ApplicationState {
    match state {
        SlotState::Occupied(state) => *state,
        SlotState::Vacant => ApplicationState::Terminated,
    }
}

/// Reserve a slot for `identity` and return `(index, generation)`, setting the
/// slot to `Loading` and installing `group` as its thread group. Prefers a
/// `Vacant` slot already bound to this identity (so re-launch reuses the slot
/// with a bumped generation), then any `Vacant` slot, then appends a fresh one
/// (§14.3).
fn reserve_slot(
    slots: &mut Vec<Slot>,
    identity: Vec<u8>,
    model: ExecutionModel,
    group: ThreadGroup,
) -> (usize, u32) {
    if let Some(index) = slots
        .iter()
        .position(|s| matches!(s.state, SlotState::Vacant) && s.identity == identity)
    {
        let slot = &mut slots[index];
        slot.model = model;
        slot.group = group;
        slot.generation = slot.generation.wrapping_add(1);
        slot.state = SlotState::Occupied(ApplicationState::Loading);
        return (index, slot.generation);
    }
    if let Some(index) = slots
        .iter()
        .position(|s| matches!(s.state, SlotState::Vacant))
    {
        let slot = &mut slots[index];
        slot.identity = identity;
        slot.model = model;
        slot.group = group;
        slot.generation = slot.generation.wrapping_add(1);
        slot.state = SlotState::Occupied(ApplicationState::Loading);
        return (index, slot.generation);
    }
    slots.push(Slot {
        identity,
        model,
        generation: 1,
        state: SlotState::Occupied(ApplicationState::Loading),
        group,
    });
    (slots.len() - 1, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;

    fn request(identity: &[u8]) -> OwnedLaunchRequest {
        OwnedLaunchRequest::new(ExecutionModel::ThreadGroup, identity.to_vec())
    }

    #[test]
    fn process_request_is_unsupported() {
        let manager = ApplicationManager::new();
        let req = OwnedLaunchRequest::new(ExecutionModel::Process, b"app".to_vec());
        let err = manager.launch(req, |_| Ok(())).unwrap_err();
        assert!(matches!(
            err,
            ApplicationLaunchError::UnsupportedExecutionModel(ExecutionModel::Process)
        ));
        // The request reserved nothing.
        assert!(manager.query_by_identity(b"app").is_none());
    }

    #[test]
    fn relaunch_after_release_bumps_the_generation() {
        let manager = ApplicationManager::new();
        let first = manager.launch(request(b"app"), |_| Ok(())).unwrap();
        assert_eq!(manager.query(first).unwrap().state, ApplicationState::Running);
        manager.release(first).unwrap();

        let second = manager.launch(request(b"app"), |_| Ok(())).unwrap();
        // Same slot reused, generation bumped: distinct ABA handle (§14.4).
        assert_eq!(first.slot, second.slot);
        assert_ne!(first.generation, second.generation);
        assert!(manager.query(first).is_none());
    }

    #[test]
    fn stale_and_forged_handles_are_rejected() {
        let manager = ApplicationManager::new();
        let handle = manager.launch(request(b"app"), |_| Ok(())).unwrap();
        assert!(manager.query(handle).is_some());

        // Forged generation.
        let forged = ApplicationHandle {
            slot: handle.slot,
            generation: handle.generation.wrapping_add(1),
        };
        assert!(manager.query(forged).is_none());

        // Out-of-range slot.
        assert!(manager
            .query(ApplicationHandle {
                slot: 999,
                generation: 0,
            })
            .is_none());
    }

    #[test]
    fn failed_prepare_leaves_a_queryable_failed_slot() {
        let manager = ApplicationManager::new();
        let err = manager
            .launch(request(b"app"), |_| Err(ApplicationLaunchError::PrepareFailed))
            .unwrap_err();
        assert!(matches!(err, ApplicationLaunchError::PrepareFailed));

        let snapshot = manager.query_by_identity(b"app").unwrap();
        assert_eq!(snapshot.state, ApplicationState::Failed);
    }

    #[test]
    fn releasing_an_already_released_slot_is_rejected() {
        let manager = ApplicationManager::new();
        let handle = manager.launch(request(b"app"), |_| Ok(())).unwrap();
        manager.release(handle).unwrap();
        assert!(matches!(
            manager.release(handle),
            Err(ApplicationLaunchError::AlreadyReleased)
        ));
    }
}
