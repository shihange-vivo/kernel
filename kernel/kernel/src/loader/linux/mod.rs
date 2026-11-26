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

//! Trusted single-threaded AArch64 Linux ELF execution in the flat domain.

mod memory;
#[cfg(all(test, linux_glibc_smoke))]
mod smoke;

use super::{
    adapters::{FlatImageAllocation, KernelCodeCache, MemoryMapper, VfsElfReader},
    load_request,
    startup::{enter_elf, StartupFrame},
    RunRequest, StartupArguments, StartupError,
};
use crate::{
    error::Error,
    process::{current_process, ProcessManager},
    scheduler, sync,
    thread::{self, Builder, CleanupError, DeferredCleanup, Entry, GlobalQueueVisitor, Stack},
    time::Tick,
    vfs,
};
use alloc::sync::Arc;
use blueos_loader::{map_elf_for_interpreter, InterpreterImage, LoadError};
use core::{
    ffi::{c_void, CStr},
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
use memory::LinuxMemory;
use spin::Mutex;

pub(crate) use memory::{MAP_ANONYMOUS, PAGE_SIZE};

type FlatElf = InterpreterImage<FlatImageAllocation>;

#[derive(Debug)]
pub enum LinuxRunError {
    File(Error),
    Load(LoadError),
    Startup(StartupError),
    InterpreterMissing,
    NestedInterpreter,
    InvalidPath,
    StackUnavailable,
    MemoryUnavailable,
    Start(CleanupError),
}

#[must_use = "retain process resources until its Linux thread retires"]
pub(crate) struct LinuxProcess {
    memory: Mutex<LinuxMemory>,
    launch: Launch,
    clear_child_tid: AtomicUsize,
    status: AtomicUsize,
    completed: AtomicUsize,
}

struct Launch {
    entry: usize,
    sp: usize,
}

/// Map a Linux PIE and its PT_INTERP from the VFS, then enter GNU ld.so.
/// The caller supplies entropy for AT_RANDOM and waits for the exit status.
/// argv defaults to the executable path when empty. Image loading and VFS
/// setup use the caller's stack. The QEMU smoke test uses a 16 KiB caller
/// stack and an independent 64 KiB application stack.
///
/// # Safety
/// The executable, interpreter and all code they load must be trusted. The
/// thread runs at EL1 in the shared kernel address space. Mapping protections
/// are software metadata and the process supports a single Linux thread.
/// Executable files must remain stable while the loader reads them.
pub unsafe fn run_linux_from_path(
    path: &CStr,
    request: &RunRequest<'_>,
    random: &[u8; 16],
) -> Result<u8, LinuxRunError> {
    let app = map_file(path)?;
    let interp = map_file(app.interpreter().ok_or(LinuxRunError::InterpreterMissing)?)?;
    if interp.interpreter().is_some() {
        return Err(LinuxRunError::NestedInterpreter);
    }
    let entry = interp.entry().get() as usize;
    let stack = Stack::from_size(request.stack_size).ok_or(LinuxRunError::StackUnavailable)?;
    let default_argv = [path];
    let (stack, sp) = StartupFrame::for_interpreter(
        &app,
        interp.load_bias() as usize,
        stack,
        StartupArguments {
            argv: if request.argv.is_empty() {
                &default_argv
            } else {
                request.argv
            },
            envp: request.envp,
            page_size: PAGE_SIZE,
            execfn: request.execfn.or(Some(path)),
            random: Some(random),
        },
    )
    .map_err(LinuxRunError::Startup)?;
    let memory = LinuxMemory::new([app, interp]).map_err(|_| LinuxRunError::MemoryUnavailable)?;

    let parent = current_process();
    let manager = ProcessManager::get();
    let parent = parent.as_ref().unwrap_or_else(|| manager.root_process());
    let process = manager
        .create_process(Arc::downgrade(parent))
        .map_err(LinuxRunError::File)?;
    let linux = process.linux.call_once(|| LinuxProcess {
        memory: Mutex::new(memory),
        launch: Launch { entry, sp },
        clear_child_tid: AtomicUsize::new(0),
        status: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
    });
    let reaped = process.clone();
    let cleanup = DeferredCleanup::new(move || {
        let files = reaped.fd_manager().irqsave_lock().take_all();
        files.close_all();
        let linux = reaped.linux.get().unwrap();
        linux.completed.store(1, Ordering::Release);
        let _result = sync::atomic_wake(&linux.completed, usize::MAX);
    })
    .map_err(|error| {
        manager.destroy_process(process.pid());
        let files = process.fd_manager().irqsave_lock().take_all();
        files.close_all();
        LinuxRunError::Start(error)
    })?;
    let launch = ptr::from_ref(&linux.launch).cast_mut().cast::<c_void>();
    let mut thread = Builder::new(Entry::Posix(bootstrap, launch))
        .set_stack(stack)
        .set_initial_sp(sp)
        .build();
    if !process.add_thread(thread.clone()) {
        GlobalQueueVisitor::remove(&mut thread);
        manager.destroy_process(process.pid());
        cleanup.run();
        return Err(LinuxRunError::Start(CleanupError::QueueFailed));
    }
    thread.lock().set_deferred_cleanup(cleanup);
    if scheduler::queue_ready_thread(thread::IDLE, thread.clone()).is_err() {
        process.remove_thread(&mut thread);
        GlobalQueueVisitor::remove(&mut thread);
        manager.destroy_process(process.pid());
        let cleanup = thread.lock().take_cleanup();
        if let Some(thread::Cleanup::Deferred(cleanup)) = cleanup {
            cleanup.run();
        }
        return Err(LinuxRunError::Start(CleanupError::QueueFailed));
    }
    while linux.completed.load(Ordering::Acquire) == 0 {
        let _result = sync::atomic_wait(&linux.completed, 0, Tick::MAX);
    }
    Ok(linux.status.load(Ordering::Relaxed) as u8)
}

fn map_file(path: &CStr) -> Result<FlatElf, LinuxRunError> {
    let path = path.to_str().map_err(|_| LinuxRunError::InvalidPath)?;
    let file = vfs::open_path(path, libc::O_RDONLY, 0).map_err(LinuxRunError::File)?;
    let reader = VfsElfReader::new(file).map_err(LinuxRunError::Load)?;
    map_elf_for_interpreter(
        reader,
        load_request(),
        PAGE_SIZE as u64,
        MemoryMapper::new(),
        &mut KernelCodeCache::new(),
    )
    .map_err(LinuxRunError::Load)
}

extern "C" fn bootstrap(launch: *mut c_void) {
    // SAFETY: the process retains this immutable launch data through retirement.
    let launch = unsafe { &*launch.cast::<Launch>() };
    // SAFETY: run_linux_from_path authorizes execution and retains both images.
    unsafe { enter_elf(launch.entry, launch.sp) }
}

impl LinuxProcess {
    pub(crate) fn brk(&self, end: usize) -> usize {
        self.memory.lock().brk(end)
    }

    pub(crate) fn mmap(
        &self,
        address: usize,
        len: usize,
        prot: usize,
        flags: usize,
        file: Option<(&vfs::File, u64)>,
    ) -> Result<usize, i32> {
        self.memory.lock().mmap(address, len, prot, flags, file)
    }

    pub(crate) fn munmap(&self, address: usize, len: usize) -> Result<(), i32> {
        self.memory.lock().munmap(address, len)
    }

    pub(crate) fn mprotect(&self, address: usize, len: usize, prot: usize) -> Result<(), i32> {
        self.memory.lock().mprotect(address, len, prot)
    }

    pub(crate) fn set_tid_address(&self, address: usize) {
        self.clear_child_tid.store(address, Ordering::Relaxed);
    }

    pub(crate) fn record_exit(&self, status: usize) {
        let addr = self.clear_child_tid.load(Ordering::Relaxed);
        if addr != 0 {
            // SAFETY: the trusted Linux caller keeps its clear-child-TID word
            // live and writable until the thread exits.
            unsafe { (addr as *mut i32).write(0) };
        }
        self.status.store(status & 0xff, Ordering::Relaxed);
    }
}
