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
use spin::Once;

// Direct RTOS threads share a system descriptor table without acquiring
// process membership. Process-owned threads use their process's own table.
static SYSTEM_FD_MANAGER: Once<crate::sync::SpinLock<FdManager>> = Once::new();
static SYSTEM_STDIO_READY: Once<()> = Once::new();

pub(crate) fn system_fd_manager() -> &'static crate::sync::SpinLock<FdManager> {
    SYSTEM_FD_MANAGER.call_once(|| crate::sync::SpinLock::new(FdManager::new()))
}

/// Standard file descriptors
pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const STDERR_FILENO: c_int = 2;
/// First available file descriptor
pub const FIRST_FD: usize = 3;

pub(crate) fn init_system_stdio() -> Result<(), Error> {
    init_stdio_with(system_fd_manager(), &SYSTEM_STDIO_READY, open_console)
}

fn open_console(flags: c_int) -> Result<Arc<dyn FileOps>, Error> {
    Ok(Arc::new(path::open_path("/dev/console", flags, 0o666)?))
}

fn prepare_stdio(
    mut open: impl FnMut(c_int) -> Result<Arc<dyn FileOps>, Error>,
) -> Result<[Arc<dyn FileOps>; FIRST_FD], Error> {
    Ok([
        open(libc::O_RDONLY)?,
        open(libc::O_WRONLY)?,
        open(libc::O_WRONLY)?,
    ])
}

fn init_stdio_with(
    table: &crate::sync::SpinLock<FdManager>,
    initialized: &Once<()>,
    open: impl FnMut(c_int) -> Result<Arc<dyn FileOps>, Error>,
) -> Result<(), Error> {
    initialized
        .try_call_once(|| {
            // Opening and partial-failure cleanup happen without the fd lock.
            let files = prepare_stdio(open)?;
            let replaced = {
                let mut manager = table.irqsave_lock();
                manager.install_stdio(files)
            };
            // Old file objects may release VFS resources on their last drop.
            drop(replaced);
            Ok(())
        })
        .map(|_| ())
}

/// File descriptor manager
#[must_use = "keep the descriptor table alive while its files are in use"]
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

    /// Prepare a process's standard streams before publishing its fd table.
    pub fn with_stdio() -> Result<Self, Error> {
        let files = prepare_stdio(open_console)?;
        let mut manager = Self::new();
        drop(manager.install_stdio(files));
        Ok(manager)
    }

    /// Only move handles while locked; the caller drops old handles unlocked.
    #[must_use = "release replaced file handles after unlocking the fd table"]
    fn install_stdio(
        &mut self,
        [stdin, stdout, stderr]: [Arc<dyn FileOps>; FIRST_FD],
    ) -> [Option<Arc<dyn FileOps>>; FIRST_FD] {
        [
            self.fds[STDIN_FILENO as usize].replace(stdin),
            self.fds[STDOUT_FILENO as usize].replace(stdout),
            self.fds[STDERR_FILENO as usize].replace(stderr),
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

#[cfg(test)]
mod tests;
