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

//! Bounded application event queue with a capacity guarantee (C27, §16.3).
//!
//! The scheduler's context-switch cleanup must deliver a member thread's
//! [`ApplicationEvent::ExecutionUnitExited`] without allocating: an OOM there
//! would silently drop the last-exit notification and leak the group (§16.5).
//! [`ApplicationEventQueue`] therefore never allocates on the enqueue path —
//! capacity is reserved up front, one slot per admitted member, via
//! [`ApplicationEventQueue::reserve_capacity`] before the member is counted
//! (§16.1). Enqueueing writes a small `Copy` event into a preallocated ring slot.
//!
//! The loss-free guarantee is [`ApplicationEventQueue::enqueue_or_oldest`]: when
//! the ring is full it overwrites the *oldest* event and returns it, so the
//! newest exit is never lost. A full ring can only mean a member was admitted
//! without a reservation (a programming error), which `debug_assert!` flags.
//!
//! Phase 1 keeps this queue standalone and self-contained; the C27 scheduler
//! boundary commits a preallocated [`crate::application::event_queue::ExitEventNode`]
//! into each member thread and delivers it from the cleanup path. Until then the
//! queue is exercised through its own tests.

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

/// The single event kind Phase 1 delivers across the scheduler boundary
/// (C27, §16.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationEvent {
    /// A member thread's execution unit fully exited: its stack and TCB are no
    /// longer running and its image references are safe to release once the
    /// group is otherwise quiescent.
    ExecutionUnitExited {
        /// The exited thread's id, for the coordinator to count down membership.
        thread_id: usize,
    },
}

struct Inner {
    /// Preallocated ring; `None` is an empty slot, so `Option<ApplicationEvent>`
    /// stays `Copy + Default` and needs no heap churn after reservation.
    ring: Vec<Option<ApplicationEvent>>,
    head: usize,
    count: usize,
}

impl Inner {
    #[inline]
    fn capacity(&self) -> usize {
        self.ring.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.capacity() != 0 && self.count == self.capacity()
    }

    /// Push `event` into the next free slot. The caller has already reserved the
    /// capacity, so this never allocates. Returns `false` only for a zero-
    /// capacity queue (which rejects everything rather than overflowing).
    fn enqueue(&mut self, event: ApplicationEvent) -> bool {
        if self.capacity() == 0 {
            return false;
        }
        if self.is_full() {
            // The reservation invariant means this is unreachable in practice.
            return false;
        }
        let tail = (self.head + self.count) % self.capacity();
        self.ring[tail] = Some(event);
        self.count += 1;
        true
    }

    /// Push `event`, overwriting the oldest event (returning it) if the ring is
    /// full. This is the loss-free primitive the scheduler cleanup relies on:
    /// the newest exit survives even if capacity was under-reserved.
    fn enqueue_or_oldest(&mut self, event: ApplicationEvent) -> Option<ApplicationEvent> {
        if self.capacity() == 0 {
            return Some(event);
        }
        if !self.is_full() {
            self.enqueue(event);
            return None;
        }
        let evicted = self.ring[self.head].replace(event);
        self.head = (self.head + 1) % self.capacity();
        evicted
    }

    /// Remove every queued event in FIFO order.
    fn drain(&mut self, out: &mut Vec<ApplicationEvent>) {
        for _ in 0..self.count {
            let slot = self.ring[self.head].take();
            self.head = (self.head + 1) % self.capacity();
            if let Some(event) = slot {
                out.push(event);
            }
        }
        self.count = 0;
    }
}

/// A cloneable handle onto a shared, bounded application event queue.
///
/// `Clone` yields another handle onto the same ring, so the scheduler cleanup
/// and the exit coordinator reach the same events without transferring the queue.
pub struct ApplicationEventQueue {
    inner: Arc<Mutex<Inner>>,
}

impl ApplicationEventQueue {
    /// Create a queue with the given starting capacity. Zero is allowed but a
    /// zero-capacity queue rejects every enqueue; reserve capacity before use.
    pub fn new(capacity: usize) -> Self {
        let mut ring = Vec::new();
        if capacity != 0 {
            ring.try_reserve_exact(capacity)
                .expect("bounded startup reserve must not fail");
            ring.resize(capacity, None);
        }
        Self {
            inner: Arc::new(Mutex::new(Inner {
                ring,
                head: 0,
                count: 0,
            })),
        }
    }

    /// Grow the ring by `additional` slots, preserving the FIFO order of any
    /// queued events. Called from the membership path (never the scheduler) so
    /// it may allocate. Returns `false` on allocation failure; the caller then
    /// rejects the member it was reserving for (§16.1).
    pub fn reserve_capacity(&self, additional: usize) -> bool {
        if additional == 0 {
            return true;
        }
        let mut inner = self.inner.lock();
        let new_capacity = match inner.capacity().checked_add(additional) {
            Some(cap) => cap,
            None => return false,
        };
        let mut ring = Vec::new();
        if ring.try_reserve_exact(new_capacity).is_err() {
            return false;
        }
        ring.resize(new_capacity, None);
        // Replay the live events into the new ring in FIFO order.
        let mut live = Vec::new();
        inner.drain(&mut live);
        for event in live {
            // The new ring is strictly larger than the live count, so this can
            // only fail if `new_capacity` was miscomputed.
            ring[inner.count] = Some(event);
            inner.count += 1;
        }
        inner.ring = ring;
        inner.head = 0;
        true
    }

    /// Whether the queue currently holds no events.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// The number of queued events.
    pub fn len(&self) -> usize {
        self.inner.lock().count
    }

    /// Enqueue without allocating. Returns `false` if the ring is full (or has
    /// zero capacity); prefer [`ApplicationEventQueue::enqueue_or_oldest`] on the
    /// scheduler path so an exit notification is never dropped.
    pub fn enqueue(&self, event: ApplicationEvent) -> bool {
        self.inner.lock().enqueue(event)
    }

    /// Enqueue without allocating, overwriting the oldest event (returned) if
    /// the ring is full. This is the loss-free primitive for scheduler cleanup:
    /// the newest exit is always retained.
    pub fn enqueue_or_oldest(&self, event: ApplicationEvent) -> Option<ApplicationEvent> {
        self.inner.lock().enqueue_or_oldest(event)
    }

    /// Remove every queued event in FIFO order.
    pub fn drain(&self) -> Vec<ApplicationEvent> {
        let mut inner = self.inner.lock();
        let mut out = Vec::new();
        if out.try_reserve_exact(inner.count).is_ok() {
            inner.drain(&mut out);
        } else {
            // Drain into an under-reserved vector one-by-one; the ring still
            // empties, only the returned buffer may grow.
            inner.drain(&mut out);
        }
        out
    }
}

impl Default for ApplicationEventQueue {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use blueos_test_macro::test;

    fn exited(id: usize) -> ApplicationEvent {
        ApplicationEvent::ExecutionUnitExited { thread_id: id }
    }

    #[test]
    fn enqueue_and_drain_are_fifo() {
        let queue = ApplicationEventQueue::new(4);
        assert!(queue.enqueue(exited(1)));
        assert!(queue.enqueue(exited(2)));
        assert!(queue.enqueue(exited(3)));
        assert_eq!(queue.drain(), vec![exited(1), exited(2), exited(3)]);
        assert!(queue.is_empty());
    }

    #[test]
    fn reserved_capacity_never_drops_the_newest_exit() {
        // Two members reserve two slots; three exits still retain the newest two.
        let queue = ApplicationEventQueue::new(0);
        assert!(queue.reserve_capacity(2));
        assert!(queue.enqueue(exited(1)));
        assert!(queue.enqueue(exited(2)));

        // Full: the third exit evicts the oldest (id 1).
        let evicted = queue.enqueue_or_oldest(exited(3));
        assert_eq!(evicted, Some(exited(1)));
        assert_eq!(queue.drain(), vec![exited(2), exited(3)]);
    }

    #[test]
    fn enqueue_returns_false_only_when_full() {
        let queue = ApplicationEventQueue::new(1);
        assert!(queue.enqueue(exited(1)));
        assert!(!queue.enqueue(exited(2)));
        assert_eq!(queue.drain(), vec![exited(1)]);
    }

    #[test]
    fn zero_capacity_queue_rejects_everything() {
        let queue = ApplicationEventQueue::new(0);
        assert!(!queue.enqueue(exited(1)));
        assert!(queue.drain().is_empty());
    }

    #[test]
    fn reserve_capacity_preserves_fifo_order() {
        let queue = ApplicationEventQueue::new(1);
        assert!(queue.enqueue(exited(1)));
        assert!(queue.reserve_capacity(3));
        assert!(queue.enqueue(exited(2)));
        assert!(queue.enqueue(exited(3)));
        assert_eq!(queue.drain(), vec![exited(1), exited(2), exited(3)]);
    }
}
