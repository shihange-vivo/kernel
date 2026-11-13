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

//! Thread-group descriptors, shared by its members without a Process.

use crate::{
    sync::SpinLock,
    vfs::{fd_manager::FdManager, FileOps},
};
use alloc::sync::Arc;

/// File handles installed as descriptors 0, 1 and 2 for a new thread group.
/// Each installed descriptor is closed when the group finishes. Keep the
/// underlying file objects valid through those close calls.
/// Installation shares the supplied objects and offsets; it does not reopen them.
#[must_use = "install the streams when preparing the thread group"]
pub struct StandardIo {
    pub stdin: Arc<dyn FileOps>,
    pub stdout: Arc<dyn FileOps>,
    pub stderr: Arc<dyn FileOps>,
}

#[must_use = "retain the descriptors through group finalization"]
pub(super) struct ThreadGroupFiles {
    pub(super) table: SpinLock<FdManager>,
}

impl ThreadGroupFiles {
    pub(super) fn new(table: FdManager) -> Self {
        Self {
            table: SpinLock::new(table),
        }
    }

    pub(super) fn close_all(&self) {
        let files = self.table.irqsave_lock().take_all();
        files.close_all();
    }
}

impl Drop for ThreadGroupFiles {
    fn drop(&mut self) {
        // Also covers preparation failure before membership is installed.
        self.close_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{ThreadGroup, ThreadGroupExit, ThreadGroupInner},
        *,
    };
    use crate::{
        arch,
        error::Error,
        scheduler,
        thread::{Builder, Entry, Stack},
        vfs::{self, FileAttr, OpenFlags},
    };
    use alloc::boxed::Box;
    use blueos_header::thread::SpawnArgs;
    use blueos_test_macro::test;
    use core::{
        ffi::{c_void, CStr},
        sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
    };
    use spin::Mutex;

    struct Observed {
        path: &'static CStr,
        byte: u8,
        normal: bool,
        release: AtomicBool,
        cleaned: AtomicBool,
        owner_dropped: AtomicBool,
        fd: AtomicI32,
        closes: AtomicUsize,
        writes: AtomicUsize,
        group: Mutex<alloc::sync::Weak<ThreadGroupInner>>,
    }

    #[must_use]
    struct Owner(Arc<Observed>);
    impl Drop for Owner {
        fn drop(&mut self) {
            assert_eq!(self.0.closes.load(Ordering::Acquire), 4);
            self.0.owner_dropped.store(true, Ordering::Release);
        }
    }

    #[must_use]
    struct ProbeFile {
        observed: Arc<Observed>,
        fail_close: bool,
    }
    impl FileOps for ProbeFile {
        fn read(&self, bytes: &mut [u8]) -> Result<usize, Error> {
            if let Some(byte) = bytes.first_mut() {
                *byte = self.observed.byte;
                Ok(1)
            } else {
                Ok(0)
            }
        }
        fn write(&self, bytes: &[u8]) -> Result<usize, Error> {
            self.observed
                .writes
                .fetch_add(bytes.len(), Ordering::Release);
            Ok(bytes.len())
        }
        fn close(&self) -> Result<(), Error> {
            assert!(arch::local_irq_enabled());
            assert!(!crate::irq::is_in_irq());
            assert!(!self.observed.owner_dropped.load(Ordering::Acquire));
            let group = self.observed.group.lock().upgrade().unwrap();
            assert!(group.state.try_irqsave_lock().is_some());
            assert!(group.fd_manager().try_irqsave_lock().is_some());
            scheduler::yield_me();
            self.observed.closes.fetch_add(1, Ordering::Release);
            if self.fail_close {
                Err(crate::error::code::EIO)
            } else {
                Ok(())
            }
        }
        fn stat(&self) -> FileAttr {
            FileAttr::default()
        }
        fn flags(&self) -> OpenFlags {
            OpenFlags::empty()
        }
        fn set_flags(&self, _: OpenFlags) {}
    }

    fn prepare(path: &'static CStr, byte: u8, normal: bool) -> (ThreadGroup, Arc<Observed>) {
        let observed = Arc::new(Observed {
            path,
            byte,
            normal,
            release: AtomicBool::new(false),
            cleaned: AtomicBool::new(false),
            owner_dropped: AtomicBool::new(false),
            fd: AtomicI32::new(-1),
            closes: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            group: Mutex::new(alloc::sync::Weak::new()),
        });
        let file = |fail_close| -> Arc<dyn FileOps> {
            Arc::new(ProbeFile {
                observed: observed.clone(),
                fail_close,
            })
        };
        let mut table = FdManager::from_stdio([file(false), file(false), file(true)]);
        assert_eq!(table.alloc_fd(file(false)), 3);
        let group = ThreadGroupInner::prepare(Box::new(Owner(observed.clone())), table);
        *observed.group.lock() = Arc::downgrade(&group);
        let thread =
            Builder::new(Entry::Posix(main, Arc::as_ptr(&observed).cast_mut().cast())).build();
        thread
            .lock()
            .set_deferred_cleanup(group.main_cleanup().unwrap());
        (group.install(thread), observed)
    }

    fn write(fd: i32, bytes: &[u8]) {
        assert_eq!(
            crate::syscalls::write::handle(fd, bytes.as_ptr().cast(), bytes.len()),
            bytes.len() as core::ffi::c_long
        );
    }

    extern "C" fn child(pointer: *mut c_void) {
        let observed = unsafe { &*pointer.cast::<Observed>() };
        assert!(crate::process::current_process().is_none());
        let mut byte = 0;
        assert_eq!(
            crate::syscalls::read::handle(
                observed.fd.load(Ordering::Acquire),
                (&raw mut byte).cast(),
                1
            ),
            1
        );
        assert_eq!(byte, observed.byte);
        write(1, b"child");
        // This descriptor belongs to the group, so its removal is visible to main.
        assert_eq!(crate::syscalls::close::handle(3), 0);
        // Finish I/O before retirement, while this group's table is current.
        assert_eq!(
            crate::syscalls::read::handle(0, (&raw mut byte).cast(), 1),
            1
        );
        assert_eq!(byte, observed.byte);
        write(2, b"leaving");
    }

    extern "C" fn cleanup(pointer: *mut c_void) {
        let observed = unsafe { &*pointer.cast::<Observed>() };
        assert!(arch::local_irq_enabled());
        assert!(!crate::irq::is_in_irq());
        assert!(crate::process::current_process().is_none());
        assert!(super::super::for_thread(scheduler::current_thread_id()).is_none());
        assert!(!observed.owner_dropped.load(Ordering::Acquire));
        observed.cleaned.store(true, Ordering::Release);
    }

    extern "C" fn main(pointer: *mut c_void) {
        let observed = unsafe { &*pointer.cast::<Observed>() };
        assert!(crate::process::current_process().is_none());
        while !observed.release.load(Ordering::Acquire) {
            scheduler::yield_me();
        }
        let mut byte = 0;
        assert_eq!(
            crate::syscalls::read::handle(0, (&raw mut byte).cast(), 1),
            1
        );
        assert_eq!(byte, observed.byte);
        let fd = crate::syscalls::open::handle(
            observed.path.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR,
            0o600,
        );
        // Both concurrent groups get the same integer in separate tables.
        assert_eq!(fd, 4);
        write(fd, &[observed.byte, b'!']);
        assert_eq!(crate::syscalls::lseek::handle(fd, 0, libc::SEEK_SET), 0);
        observed.fd.store(fd, Ordering::Release);
        let stack = Stack::from_size(16 * 1024).unwrap();
        let args = SpawnArgs {
            spawn_hook: None,
            stack_start: stack.base(),
            stack_size: stack.size(),
            entry: child,
            arg: pointer,
            cleanup: Some(cleanup),
        };
        // Thread handles encode kernel addresses; the high bit may be set.
        assert_ne!(crate::syscalls::create_thread::handle(&raw const args), -1);
        assert_eq!(crate::syscalls::thread_group_begin_exit::handle(7), 0);
        assert!(observed.cleaned.load(Ordering::Acquire));
        assert_eq!(observed.closes.load(Ordering::Acquire), 1);
        assert_eq!(
            crate::syscalls::read::handle(3, (&raw mut byte).cast(), 1),
            -(libc::EBADF as isize)
        );
        // The child's read advanced the shared file offset.
        assert_eq!(
            crate::syscalls::read::handle(fd, (&raw mut byte).cast(), 1),
            1
        );
        assert_eq!(byte, b'!');
        assert_eq!(crate::syscalls::close::handle(fd), 0);
        drop(stack);
        if observed.normal {
            crate::syscalls::thread_group_finish_exit::handle();
            unreachable!();
        }
        // Retirement without finish_exit still closes group resources.
    }

    #[test]
    fn thread_group_files_are_shared_with_children_and_isolated_between_groups() {
        for _ in 0..3 {
            let (mut first, a) = prepare(c"/application-files-a", b'A', true);
            let (mut second, b) = prepare(c"/application-files-b", b'B', false);
            first.start().unwrap();
            second.start().unwrap();
            assert_eq!(
                first.start(),
                Err(super::super::ThreadGroupError::AlreadyStarted)
            );
            a.release.store(true, Ordering::Release);
            b.release.store(true, Ordering::Release);
            for (thread_group, observed, expected) in [
                (&first, &a, ThreadGroupExit::Code(7)),
                (&second, &b, ThreadGroupExit::Aborted),
            ] {
                assert_eq!(thread_group.wait(), Ok(expected));
                assert_eq!(thread_group.group.fd_manager().irqsave_lock().count(), 0);
                assert_eq!(observed.closes.load(Ordering::Acquire), 4);
                assert_eq!(observed.writes.load(Ordering::Acquire), 12);
                assert!(observed.owner_dropped.load(Ordering::Acquire));
                assert!(thread_group.thread().process().is_none());
            }
        }
        assert_eq!(vfs::syscalls::unlink(c"/application-files-a".as_ptr()), 0);
        assert_eq!(vfs::syscalls::unlink(c"/application-files-b".as_ptr()), 0);
    }

    #[test]
    fn cancelling_prepared_thread_group_closes_files_before_image_release() {
        let (thread_group, observed) = prepare(c"/application-cancelled", b'C', false);
        let group = thread_group.group.clone();
        drop(thread_group);
        assert_eq!(group.fd_manager().irqsave_lock().count(), 0);
        assert_eq!(observed.closes.load(Ordering::Acquire), 4);
        assert!(observed.owner_dropped.load(Ordering::Acquire));
        drop(group);
        assert_eq!(observed.closes.load(Ordering::Acquire), 4);
    }
}
