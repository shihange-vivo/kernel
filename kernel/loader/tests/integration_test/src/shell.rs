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

//! Run the production Rust shell through the kernel's one-call loader entry.
//! The test stages the shell ELF in the target VFS, then `loader::run`
//! performs the complete flow: open, load, startup frame, thread scheduling
//! and exit. The application runs as an RTOS thread group with its own
//! descriptor table, without requiring a Process.

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use blueos::{
    loader::{RunRequest, StandardIo, ThreadGroupExit},
    scheduler,
    thread::{Builder, DeferredCleanup, Entry, Stack, IDLE},
    vfs::{self, FileOps},
};
use blueos_test_macro::test;
use core::{
    ffi::{c_char, CStr},
    sync::atomic::{AtomicUsize, Ordering},
};

unsafe extern "C" {
    static SHELL_TEST_ELF_PATH: *const c_char;
}

const IMAGE_PATH: &str = "/shell.elf";
const INPUT_PATH: &str = "/shell-input";
const OUTPUT_PATH: &str = "/shell-output";
const ERROR_PATH: &str = "/shell-error";
const CREATED_PATH: &str = "/shell-created";
const SCRIPT: &[u8] =
    b"echo shell-group-ready\necho persisted-by-shell > /shell-created\ncat /shell-created\nexit\n";
const LOADER_STACK_SIZE: usize = 12 * 1024;
const STACK_GUARD_SIZE: usize = 1024;
const STACK_GUARD_BYTE: u8 = 0xa5;

/// Copy a host fixture into the target VFS so the run entry opens it by path.
fn stage_image(path: &str, host: &CStr) {
    use semihosting::io::Read;
    let mut source = semihosting::fs::File::open(host).expect("open host shell ELF");
    let file = vfs::open_path(path, libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY, 0o600)
        .expect("create target shell ELF");
    let len = usize::try_from(source.metadata().unwrap().len()).unwrap();
    file.resize(len).expect("size target shell ELF");
    let mut copied = 0;
    let mut buffer = [0; 512];
    loop {
        let count = source.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        let mut written = 0;
        while written < count {
            let size = file.write(&buffer[written..count]).unwrap();
            assert!(size != 0);
            written += size;
        }
        copied += count;
    }
    assert_eq!(copied, len);
}

#[test]
fn test_run_loads_shell_as_bare_thread_group() {
    // Exercise loading within an explicit caller-stack budget. The guard sits
    // below the execution stack; its owning storage stays here through cleanup.
    // RunRequest::stack_size controls the application's stack independently.
    let done = Arc::new(AtomicUsize::new(0));
    let completed = done.clone();
    let storage = Stack::from_size(LOADER_STACK_SIZE + STACK_GUARD_SIZE)
        .expect("shell loader test stack storage");
    // SAFETY: this fresh allocation is exclusively owned and unpublished. Only
    // the range above the initialized guard is handed to the execution thread.
    let base = unsafe {
        storage
            .base()
            .write_bytes(STACK_GUARD_BYTE, STACK_GUARD_SIZE);
        storage.base().add(STACK_GUARD_SIZE)
    };
    let stack = Stack::from_raw(base, LOADER_STACK_SIZE).expect("shell loader execution stack");
    let thread = Builder::new(Entry::Closure(Box::new(run_shell_repeatedly)))
        .set_stack(stack)
        .build();
    assert!(thread.process().is_none());
    // Publish completion after the entry has returned and dropped its captures.
    thread.lock().set_deferred_cleanup(
        DeferredCleanup::new(move || {
            completed.store(1, Ordering::Release);
            blueos::sync::wake(&completed);
        })
        .expect("shell loader test cleanup"),
    );
    assert_eq!(scheduler::queue_ready_thread(IDLE, thread.clone()), Ok(()));
    blueos::sync::wait_until(1, &done);
    // SAFETY: deferred cleanup runs after the entry returns. The node retains
    // its borrowed stack descriptor, storage owns the allocation, and the guard
    // lies outside the execution range so it has no concurrent accesses.
    let guard = unsafe { core::slice::from_raw_parts(storage.base(), STACK_GUARD_SIZE) };
    assert!(
        guard.iter().all(|&byte| byte == STACK_GUARD_BYTE),
        "shell loading exceeded its caller-stack budget"
    );
}

fn run_shell_repeatedly() {
    // SAFETY: the linker provides this live host fixture path.
    let host = unsafe { CStr::from_ptr(SHELL_TEST_ELF_PATH) };
    stage_image(IMAGE_PATH, host);

    for _ in 0..5 {
        assert!(blueos::process::current_process().is_none());
        let input = vfs::open_path(
            INPUT_PATH,
            libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
            0o600,
        )
        .unwrap();
        assert_eq!(input.write(SCRIPT).unwrap(), SCRIPT.len());
        input.close().unwrap();
        let stdio = StandardIo {
            stdin: Arc::new(vfs::open_path(INPUT_PATH, libc::O_RDONLY, 0).unwrap()),
            stdout: Arc::new(
                vfs::open_path(
                    OUTPUT_PATH,
                    libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
                    0o600,
                )
                .unwrap(),
            ),
            stderr: Arc::new(
                vfs::open_path(
                    ERROR_PATH,
                    libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
                    0o600,
                )
                .unwrap(),
            ),
        };
        let request = RunRequest {
            argv: &[c"shell"],
            stdio: Some(&stdio),
            ..Default::default()
        };
        // SAFETY: the staged shell is trusted native code using the standard ELF
        // initial-stack entry; QEMU's coherent test execution publishes its code.
        let status = unsafe { blueos::loader::run(IMAGE_PATH, &request) }.unwrap();
        // The shell's main returns after its service thread exits; libc fini runs.
        assert_eq!(status, ThreadGroupExit::Code(0));
        assert_eq!(read_file(CREATED_PATH), b"persisted-by-shell\n");
        let output = read_file(OUTPUT_PATH);
        for expected in [
            b"Hello, shell!".as_slice(),
            b"shell-group-ready",
            b"persisted-by-shell",
        ] {
            assert!(
                output
                    .windows(expected.len())
                    .any(|bytes| bytes == expected),
                "loaded shell did not produce expected output"
            );
        }
        assert!(read_file(ERROR_PATH).is_empty());
        // Removing it forces the next run to create the file again.
        assert_eq!(vfs::syscalls::unlink(c"/shell-created".as_ptr()), 0);
    }

    assert_eq!(vfs::syscalls::unlink(c"/shell.elf".as_ptr()), 0);
    assert_eq!(vfs::syscalls::unlink(c"/shell-input".as_ptr()), 0);
    assert_eq!(vfs::syscalls::unlink(c"/shell-output".as_ptr()), 0);
    assert_eq!(vfs::syscalls::unlink(c"/shell-error".as_ptr()), 0);
}

fn read_file(path: &str) -> Vec<u8> {
    let file = vfs::open_path(path, libc::O_RDONLY, 0).unwrap();
    let mut bytes = vec![0; usize::try_from(file.file_len().unwrap()).unwrap()];
    file.read_exact_at(0, &mut bytes).unwrap();
    file.close().unwrap();
    bytes
}
