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

/// File descriptor manager
#[must_use = "retain the table while its descriptors are in use"]
pub struct FdManager {
    /// File descriptor table
    fds: Vec<Option<Arc<dyn FileOps>>>,
    /// Next available file descriptor
    next_fd: usize,
}

impl FdManager {
    /// Create new file descriptor manager
    pub fn new() -> Self {
        Self {
            fds: vec![None; FIRST_FD + 1],
            next_fd: FIRST_FD,
        }
    }

    pub fn init_stdio(&mut self) -> Result<(), Error> {
        self.init_stdio_with(|flags| Ok(Arc::new(path::open_path("/dev/console", flags, 0o666)?)))
    }

    fn init_stdio_with(
        &mut self,
        mut open: impl FnMut(i32) -> Result<Arc<dyn FileOps>, Error>,
    ) -> Result<(), Error> {
        for (fd, flags) in [libc::O_RDONLY, libc::O_WRONLY, libc::O_WRONLY]
            .into_iter()
            .enumerate()
        {
            match open(flags) {
                Ok(file) => self.fds[fd] = Some(file),
                Err(error) => {
                    self.take_all().close_all();
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn has_stdio(&self) -> bool {
        self.fds
            .get(..FIRST_FD)
            .is_some_and(|stdio| stdio.iter().all(Option::is_some))
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
                warn!("closing application descriptor failed: {:?}", error);
            }
        }
    }

    pub(crate) fn replace_stdio(
        &mut self,
        files: [Arc<dyn FileOps>; 3],
    ) -> [Option<Arc<dyn FileOps>>; 3] {
        let [stdin, stdout, stderr] = files;
        [
            self.fds[0].replace(stdin),
            self.fds[1].replace(stdout),
            self.fds[2].replace(stderr),
        ]
    }

    /// Allocate new file descriptor
    pub fn alloc_fd(&mut self, file: Arc<dyn FileOps>) -> c_int {
        let fd = self.next_fd;
        self.fds[fd] = Some(file);
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
            self.fds.resize(new_fd + 1, None);
        }

        // do dup
        let file2 = file.dup(close_on_exec)?;
        self.fds[new_fd] = Some(file2);
        self.update_next_fd(new_fd);
        Ok(new_fd as c_int)
    }

    /// Free file descriptor
    pub fn free_fd(&mut self, fd: c_int) -> Result<(), Error> {
        // close stdio is allowed
        if fd as usize >= self.fds.len() {
            warn!("[fd] free_fd: Invalid fd: {}", fd);
            return Err(code::EBADF);
        }

        if self.fds[fd as usize].is_none() {
            warn!("[fd] free_fd: Fd {} not in use", fd);
            return Err(code::EBADF);
        }

        self.fds[fd as usize] = None;
        Ok(())
    }

    /// Get file operation
    pub fn get_file_ops(&self, fd: c_int) -> Option<Arc<dyn FileOps>> {
        if fd < 0 || fd as usize >= self.fds.len() {
            warn!("[fd] get_file_ops: Invalid fd: {}", fd);
            return None;
        }

        match self.fds[fd as usize].as_ref() {
            Some(file) => Some(file.clone()),
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
            self.fds.resize(next_fd + 1, None);
        }

        self.next_fd = next_fd;
    }
}

/// Keeps the selected table owner alive while a syscall borrows its lock.
#[must_use = "retain the owner while accessing its descriptor table"]
pub(crate) enum CurrentFiles {
    #[cfg(loader_backend)]
    Application(Arc<crate::loader::application::ApplicationGroup>),
    Process(Arc<crate::process::Process>),
}

impl CurrentFiles {
    pub(crate) fn table(&self) -> &crate::sync::SpinLock<FdManager> {
        match self {
            #[cfg(loader_backend)]
            Self::Application(group) => group.fd_manager(),
            Self::Process(process) => process.fd_manager(),
        }
    }

    pub(crate) fn get() -> Option<Self> {
        #[cfg(loader_backend)]
        if let Some(group) =
            crate::loader::application::for_thread(crate::scheduler::current_thread_id())
        {
            return Some(Self::Application(group));
        }
        crate::process::current_process().map(Self::Process)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{FileAttr, OpenFlags};
    use blueos_test_macro::test;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[must_use]
    struct CloseProbe(Arc<AtomicUsize>);
    impl FileOps for CloseProbe {
        fn close(&self) -> Result<(), Error> {
            assert!(crate::arch::local_irq_enabled());
            assert!(!crate::irq::is_in_irq());
            crate::scheduler::yield_me();
            self.0.fetch_add(1, Ordering::Release);
            Ok(())
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
    fn stdio_open_failure_closes_partial_and_prepared_descriptors() {
        for fail_at in 0..3 {
            let closed = Arc::new(AtomicUsize::new(0));
            let mut table = FdManager::new();
            assert_eq!(table.alloc_fd(Arc::new(CloseProbe(closed.clone()))), 3);
            let mut opened = 0;
            let result = table.init_stdio_with(|flags| {
                assert_eq!(
                    flags,
                    if opened == 0 {
                        libc::O_RDONLY
                    } else {
                        libc::O_WRONLY
                    }
                );
                if opened == fail_at {
                    return Err(code::EIO);
                }
                opened += 1;
                Ok(Arc::new(CloseProbe(closed.clone())))
            });
            assert_eq!(result, Err(code::EIO));
            assert_eq!(table.count(), 0);
            assert_eq!(closed.load(Ordering::Acquire), fail_at + 1);
            table.close_all();
            assert_eq!(closed.load(Ordering::Acquire), fail_at + 1);
        }
    }
}
