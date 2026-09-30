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

use crate::{
    error::{code, Error},
    scheduler::{self, wait_queue, InsertMode, WaitEntry, WaitQueue},
    sync::SpinLock,
    time::Tick,
    with_iou,
};
use core::sync::atomic::{AtomicUsize, Ordering};

/// A generation counter with its own allocation-free wait queue.
///
/// Read the sequence before inspecting work, then wait on that sequence. A
/// notification between the inspection and suspension cannot be lost. The
/// signal must live in static storage because its intrusive queue contains
/// pointers into itself; waiting and notifying require a static reference.
pub struct WaitSignal {
    sequence: AtomicUsize,
    pending: SpinLock<WaitQueue>,
}

impl WaitSignal {
    pub const fn new() -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            pending: SpinLock::new(WaitQueue::new()),
        }
    }

    pub fn sequence(&self) -> usize {
        self.sequence.load(Ordering::Acquire)
    }

    /// Publish a change without taking scheduler locks. A bounded waiter will
    /// observe it even when called from the context-switch path.
    pub fn advance(&self) {
        self.sequence.fetch_add(1, Ordering::Release);
    }

    /// Publish a change and wake every waiter. This may take scheduler locks.
    pub fn notify(&'static self) {
        self.advance();
        let mut pending = self.pending.irqsave_lock();
        pending.init();
        scheduler::wake_up_all(pending);
    }

    pub fn wait(&'static self, sequence: usize, timeout: Tick) -> Result<(), Error> {
        debug_assert!(!crate::irq::is_in_irq());
        let mut pending = self.pending.irqsave_lock();
        pending.init();
        if self.sequence() != sequence {
            return Err(code::EAGAIN);
        }
        let reached_deadline;
        with_iou!(|borrowed_wait_entry| {
            let mut entry = WaitEntry::new(scheduler::current_thread());
            borrowed_wait_entry =
                wait_queue::insert(&mut pending, &mut entry, InsertMode::InsertToEnd).unwrap();
            reached_deadline = scheduler::suspend_me_for(timeout, Some(pending));
            pending = self.pending.irqsave_lock();
            borrowed_wait_entry = pending.pop(borrowed_wait_entry).unwrap();
        });
        if reached_deadline {
            Err(code::ETIMEDOUT)
        } else {
            Ok(())
        }
    }
}

// The intrusive nodes borrow their waiting threads' stacks. All access to the
// queue, including removal before a stack can return, holds the IRQ-saving lock.
unsafe impl Sync for WaitSignal {}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;

    #[test]
    fn test_wait_signal_notification_before_wait() {
        static SIGNAL: WaitSignal = WaitSignal::new();
        let sequence = SIGNAL.sequence();
        SIGNAL.notify();
        assert_eq!(SIGNAL.wait(sequence, Tick::MAX), Err(code::EAGAIN));
    }

    #[test]
    fn test_wait_signal_advance_before_wait() {
        static SIGNAL: WaitSignal = WaitSignal::new();
        let sequence = SIGNAL.sequence();
        SIGNAL.advance();
        assert_eq!(SIGNAL.wait(sequence, Tick::MAX), Err(code::EAGAIN));
    }

    #[test]
    fn test_wait_signal_timeout_removes_waiter() {
        static SIGNAL: WaitSignal = WaitSignal::new();
        for _ in 0..3 {
            assert_eq!(
                SIGNAL.wait(SIGNAL.sequence(), Tick(1)),
                Err(code::ETIMEDOUT)
            );
            assert!(SIGNAL.pending.irqsave_lock().is_empty());
            SIGNAL.notify();
        }
    }

    #[test]
    fn test_wait_signal_notification_wakes_waiter() {
        static SIGNAL: WaitSignal = WaitSignal::new();
        extern "C" fn notify_when_waiting() {
            let deadline = Tick::after(Tick::from_millis(1000));
            while SIGNAL.pending.irqsave_lock().is_empty() {
                assert!(Tick::now() < deadline, "waiter did not park");
                scheduler::yield_me();
            }
            SIGNAL.notify();
        }

        SIGNAL.pending.irqsave_lock().init();
        let sequence = SIGNAL.sequence();
        let thread =
            crate::thread::Builder::new(crate::thread::Entry::C(notify_when_waiting)).build();
        scheduler::queue_ready_thread(crate::thread::IDLE, thread).unwrap();
        assert_eq!(SIGNAL.wait(sequence, Tick::from_millis(1000)), Ok(()));
        assert!(SIGNAL.pending.irqsave_lock().is_empty());
    }
}
