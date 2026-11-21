// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
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

//! vfs_fd.rs  

use crate::{
    error::{code, Error},
    vfs::{file::FileOps, path},
};
use alloc::{sync::Arc, vec, vec::Vec};
use core::ffi::c_int;
use log::warn;

/// Standard file descriptors
pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const STDERR_FILENO: c_int = 2;
/// First available file descriptor
pub const FIRST_FD: usize = 3;

#[must_use = "retain the descriptor or close it after removing it from the table"]
pub(crate) enum FileDescriptor {
    Owned(Arc<dyn FileOps>),
    Borrowed(Arc<dyn FileOps>),
}

impl FileDescriptor {
    fn file(&self) -> &Arc<dyn FileOps> {
        match self {
            Self::Owned(file) | Self::Borrowed(file) => file,
        }
    }

    /// Release the descriptor in ordinary thread context, outside the table lock.
    pub(crate) fn close(self) -> Result<(), Error> {
        match self {
            Self::Owned(file) => file.close(),
            Self::Borrowed(_) => Ok(()),
        }
    }
}

/// File descriptor manager
#[must_use = "retain the table while its descriptors are in use"]
pub struct FdManager {
    /// File descriptor table
    fds: Vec<Option<FileDescriptor>>,
    /// Next available file descriptor
    next_fd: usize,
}

impl FdManager {
    /// Create new file descriptor manager
    pub fn new() -> Self {
        Self {
            fds: (0..=FIRST_FD).map(|_| None).collect(),
            next_fd: FIRST_FD,
        }
    }

    /// Open all standard streams before publishing the table.
    pub fn with_console() -> Result<Self, Error> {
        Self::open_stdio(|flags| Ok(Arc::new(path::open_path("/dev/console", flags, 0o666)?)))
    }

    fn open_stdio(
        mut open: impl FnMut(c_int) -> Result<Arc<dyn FileOps>, Error>,
    ) -> Result<Self, Error> {
        let mut table = Self::new();
        for (fd, flags) in [
            (STDIN_FILENO, libc::O_RDONLY),
            (STDOUT_FILENO, libc::O_WRONLY),
            (STDERR_FILENO, libc::O_WRONLY),
        ] {
            match open(flags) {
                Ok(file) => table.fds[fd as usize] = Some(FileDescriptor::Owned(file)),
                Err(error) => {
                    table.close_all();
                    return Err(error);
                }
            }
        }
        Ok(table)
    }

    /// Create a table with the supplied standard streams and a free first slot.
    pub(crate) fn from_stdio(files: [FileDescriptor; 3]) -> Self {
        let [stdin, stdout, stderr] = files;
        Self {
            fds: vec![Some(stdin), Some(stdout), Some(stderr), None],
            next_fd: FIRST_FD,
        }
    }

    /// Detach descriptors without invoking file operations under a table lock.
    pub(crate) fn take_all(&mut self) -> Self {
        core::mem::replace(
            self,
            Self {
                fds: Vec::new(),
                next_fd: FIRST_FD,
            },
        )
    }

    /// Close every detached descriptor, continuing after individual errors.
    /// The caller must hold no fd-table lock and use ordinary thread context.
    pub(crate) fn close_all(self) {
        for file in self.fds.into_iter().flatten() {
            if let Err(error) = file.close() {
                warn!("closing descriptor failed: {:?}", error);
            }
        }
    }

    /// Allocate new file descriptor
    pub fn alloc_fd(&mut self, file: Arc<dyn FileOps>) -> c_int {
        let fd = self.next_fd;
        self.fds[fd] = Some(FileDescriptor::Owned(file));
        self.update_next_fd(fd);
        fd as c_int
    }

    /// Duplicate file descriptor
    pub fn dup_fd(&mut self, fd: c_int, minfd: c_int, close_on_exec: bool) -> Result<c_int, Error> {
        let Some(file) = self.get_file_ops(fd) else {
            return Err(code::EBADF);
        };

        let mut new_fd = minfd as usize;
        if new_fd < FIRST_FD {
            new_fd = FIRST_FD;
        }
        // find minfd
        let len = self.fds.len();
        while new_fd < len && self.fds[new_fd].is_some() {
            new_fd += 1;
        }
        if new_fd >= len {
            // add capacity by std Vec, so we just +1
            self.fds.resize_with(new_fd + 1, || None);
        }

        // do dup
        let file2 = file.dup(close_on_exec)?;
        self.fds[new_fd] = Some(FileDescriptor::Owned(file2));
        self.update_next_fd(new_fd);
        Ok(new_fd as c_int)
    }

    /// Remove a descriptor so it can be closed outside the table lock.
    pub(crate) fn take_fd(&mut self, fd: c_int) -> Result<FileDescriptor, Error> {
        let Some(descriptor) = self.fds.get_mut(fd as usize).and_then(Option::take) else {
            warn!("[fd] take_fd: Invalid or unused fd: {}", fd);
            return Err(code::EBADF);
        };
        Ok(descriptor)
    }

    /// Discard a descriptor during socket setup rollback.
    pub fn free_fd(&mut self, fd: c_int) -> Result<(), Error> {
        drop(self.take_fd(fd)?);
        Ok(())
    }

    /// Get file operation
    pub fn get_file_ops(&self, fd: c_int) -> Option<Arc<dyn FileOps>> {
        if fd < 0 || fd as usize >= self.fds.len() {
            warn!("[fd] get_file_ops: Invalid fd: {}", fd);
            return None;
        }

        match self.fds[fd as usize].as_ref() {
            Some(descriptor) => Some(descriptor.file().clone()),
            None => {
                warn!("[fd] get_file_ops: Fd {} not found", fd);
                None
            }
        }
    }

    /// Check if file descriptor is valid
    pub fn is_valid_fd(&self, fd: c_int) -> bool {
        fd >= 0 && (fd as usize) < self.fds.len() && self.fds[fd as usize].is_some()
    }

    /// Get current number of allocated file descriptors
    pub fn count(&self) -> usize {
        self.fds.iter().filter(|fd| fd.is_some()).count()
    }

    fn update_next_fd(&mut self, new_fd: usize) {
        let fds_len = self.fds.len();
        // First try: find free fd from new_fd+1 to end
        let next_fd = (new_fd + 1..fds_len)
            .find(|&fd| self.fds[fd].is_none())
            .unwrap_or_else(|| {
                // Second try: find free fd from start to new_fd
                (FIRST_FD..new_fd)
                    .find(|&fd| self.fds[fd].is_none())
                    .unwrap_or(fds_len) // If still not found, use fds_len
            });

        // Extend array if needed
        if next_fd >= fds_len {
            self.fds.resize_with(next_fd + 1, || None);
        }

        self.next_fd = next_fd;
    }
}

/// Keeps the selected table owner alive while a syscall borrows its lock.
/// Exactly one variant is compiled; an unowned thread has no descriptor table.
#[must_use = "retain the owner while accessing its descriptor table"]
pub(crate) enum CurrentFiles {
    #[cfg(thread_group)]
    ThreadGroup(Arc<crate::thread_group::ThreadGroupInner>),
    #[cfg(not(thread_group))]
    Process(Arc<crate::process::Process>),
}

impl CurrentFiles {
    pub(crate) fn table(&self) -> &crate::sync::SpinLock<FdManager> {
        match self {
            #[cfg(thread_group)]
            Self::ThreadGroup(group) => group.fd_manager(),
            #[cfg(not(thread_group))]
            Self::Process(process) => process.fd_manager(),
        }
    }

    pub(crate) fn get() -> Option<Self> {
        #[cfg(thread_group)]
        {
            crate::thread_group::for_thread(crate::scheduler::current_thread_id())
                .map(Self::ThreadGroup)
        }
        #[cfg(not(thread_group))]
        {
            crate::process::current_process().map(Self::Process)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{FileAttr, OpenFlags};
    use blueos_test_macro::test;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct ConsoleStream(Arc<AtomicUsize>);

    impl FileOps for ConsoleStream {
        fn close(&self) -> Result<(), Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(code::EIO)
        }

        fn stat(&self) -> FileAttr {
            FileAttr::default()
        }

        fn flags(&self) -> OpenFlags {
            OpenFlags::empty()
        }

        fn set_flags(&self, _: OpenFlags) {}
    }

    #[test]
    fn failed_console_open_closes_all_previously_opened_streams() {
        let closes = Arc::new(AtomicUsize::new(0));
        let mut attempts = 0;
        let result = FdManager::open_stdio(|_| {
            attempts += 1;
            if attempts == 3 {
                return Err(code::EACCES);
            }
            Ok(Arc::new(ConsoleStream(closes.clone())))
        });
        assert!(matches!(result, Err(code::EACCES)));
        assert_eq!(closes.load(Ordering::Relaxed), 2);
    }

    #[cfg(thread_group)]
    #[test]
    fn redirected_stream_stays_open_until_the_caller_closes_it() {
        let closes = Arc::new(AtomicUsize::new(0));
        let stream: Arc<dyn FileOps> = Arc::new(ConsoleStream(closes.clone()));
        let redirected_table = || {
            FdManager::from_stdio(core::array::from_fn(|_| {
                FileDescriptor::Borrowed(stream.clone())
            }))
        };
        let mut first = redirected_table();
        let second = redirected_table();

        first.take_fd(STDOUT_FILENO).unwrap().close().unwrap();
        assert!(!first.is_valid_fd(STDOUT_FILENO));
        assert!(Arc::ptr_eq(
            &first.get_file_ops(STDERR_FILENO).unwrap(),
            &stream
        ));
        first.close_all();
        assert!(second.is_valid_fd(STDOUT_FILENO));
        second.close_all();
        assert_eq!(closes.load(Ordering::Relaxed), 0);

        assert_eq!(stream.close(), Err(code::EIO));
        assert_eq!(closes.load(Ordering::Relaxed), 1);
    }
}
