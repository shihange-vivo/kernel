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

use super::*;
use crate::{
    sync::SpinLock,
    vfs::file::{FileAttr, OpenFlags},
};
use alloc::sync::Weak;
use blueos_test_macro::test;
use core::sync::atomic::{AtomicUsize, Ordering};

fn check_unlocked(table: &SpinLock<FdManager>, irq_enabled: bool) {
    assert_eq!(crate::arch::local_irq_enabled(), irq_enabled);
    assert!(
        table.try_lock().is_some(),
        "stdio callback held the fd table lock"
    );
}

#[must_use = "keep the tracked file until its release is checked"]
struct CheckedFile {
    table: Weak<SpinLock<FdManager>>,
    drops: Arc<AtomicUsize>,
    irq_enabled: bool,
}

impl Drop for CheckedFile {
    fn drop(&mut self) {
        if let Some(table) = self.table.upgrade() {
            check_unlocked(&table, self.irq_enabled);
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

impl FileOps for CheckedFile {
    fn stat(&self) -> FileAttr {
        FileAttr::default()
    }
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }
    fn set_flags(&self, _: OpenFlags) {}
}

fn file(table: &Arc<SpinLock<FdManager>>, drops: &Arc<AtomicUsize>) -> Arc<dyn FileOps> {
    Arc::new(CheckedFile {
        table: Arc::downgrade(table),
        drops: drops.clone(),
        irq_enabled: crate::arch::local_irq_enabled(),
    })
}

#[test]
fn stdio_opens_and_releases_replaced_handles_outside_the_fd_lock() {
    let table = Arc::new(SpinLock::new(FdManager::new()));
    let initialized = Once::new();
    let old_drops = Arc::new(AtomicUsize::new(0));
    let new_drops = Arc::new(AtomicUsize::new(0));
    let irq_enabled = crate::arch::local_irq_enabled();
    let old = file(&table, &old_drops);
    let extra = file(&table, &new_drops);
    {
        let mut manager = table.irqsave_lock();
        manager.fds[0] = Some(old);
        assert_eq!(manager.alloc_fd(extra.clone()), FIRST_FD as c_int);
    }

    let mut flags = Vec::new();
    init_stdio_with(&table, &initialized, |mode| {
        check_unlocked(&table, irq_enabled);
        // Reenter the descriptor table while preparing a standard stream.
        assert_eq!(table.irqsave_lock().count(), 2);
        flags.push(mode);
        Ok(file(&table, &new_drops))
    })
    .unwrap();

    assert_eq!(flags, [libc::O_RDONLY, libc::O_WRONLY, libc::O_WRONLY]);
    assert_eq!(old_drops.load(Ordering::Relaxed), 1);
    let manager = table.irqsave_lock();
    assert_eq!(manager.count(), 4);
    assert!(Arc::ptr_eq(
        &manager.get_file_ops(FIRST_FD as c_int).unwrap(),
        &extra
    ));
}

#[test]
fn stdio_open_failure_preserves_the_table_and_allows_retry() {
    for fail_at in 0..FIRST_FD {
        let table = Arc::new(SpinLock::new(FdManager::new()));
        let initialized = Once::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let original = file(&table, &drops);
        table.irqsave_lock().fds[0] = Some(original.clone());
        let irq_enabled = crate::arch::local_irq_enabled();
        let mut attempts = 0;
        let result = init_stdio_with(&table, &initialized, |_| {
            check_unlocked(&table, irq_enabled);
            let index = attempts;
            attempts += 1;
            if index == fail_at {
                return Err(code::ENODEV);
            }
            Ok(file(&table, &drops))
        });
        assert_eq!(result, Err(code::ENODEV));
        assert_eq!(attempts, fail_at + 1);
        assert_eq!(drops.load(Ordering::Relaxed), fail_at);
        assert!(initialized.get().is_none());
        {
            let manager = table.irqsave_lock();
            assert_eq!(manager.count(), 1);
            assert!(Arc::ptr_eq(&manager.get_file_ops(0).unwrap(), &original));
        }

        init_stdio_with(&table, &initialized, |_| {
            check_unlocked(&table, irq_enabled);
            Ok(file(&table, &drops))
        })
        .unwrap();
        assert!(initialized.get().is_some());
        assert_eq!(table.irqsave_lock().count(), 3);
    }
}

#[test]
fn stdio_initialization_does_not_reopen_closed_or_redirected_descriptors() {
    let table = Arc::new(SpinLock::new(FdManager::new()));
    let initialized = Once::new();
    let drops = Arc::new(AtomicUsize::new(0));
    init_stdio_with(&table, &initialized, |_| Ok(file(&table, &drops))).unwrap();

    // Retain a reference until after free_fd releases its table guard.
    let stdin = table.irqsave_lock().get_file_ops(0).unwrap();
    table.irqsave_lock().free_fd(0).unwrap();
    drop(stdin);
    let redirected = file(&table, &drops);
    let previous = table.irqsave_lock().fds[1].replace(redirected.clone());
    drop(previous);

    init_stdio_with(&table, &initialized, |_| {
        panic!("successful stdio initialization must not open files again")
    })
    .unwrap();
    let manager = table.irqsave_lock();
    assert!(!manager.is_valid_fd(0));
    assert!(Arc::ptr_eq(&manager.get_file_ops(1).unwrap(), &redirected));
    assert!(manager.is_valid_fd(2));
}
