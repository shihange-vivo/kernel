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
use crate::vfs::FileOps;
use alloc::{boxed::Box, ffi::CString};
use blueos_test_macro::test;
use semihosting::io::Read;

fn stage(target: &CStr, fixture: &str) {
    let path = CString::new(alloc::format!("{}/{fixture}", env!("GLIBC_SMOKE_DIR"))).unwrap();
    let mut source = semihosting::fs::File::open(path.as_c_str()).expect("open host ELF");
    let name = target.to_str().unwrap();
    let file = vfs::open_path(name, libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY, 0o600)
        .expect("create VFS ELF");
    let len = source.metadata().unwrap().len() as usize;
    file.resize(len).expect("resize VFS ELF");
    let mut copied = 0;
    let mut buffer = [0; 512];
    while copied < len {
        let size = buffer.len().min(len - copied);
        source
            .read_exact(&mut buffer[..size])
            .expect("read host ELF");
        let mut written = 0;
        while written < size {
            let count = file.write(&buffer[written..size]).expect("write VFS ELF");
            assert!(count > 0);
            written += count;
        }
        copied += size;
    }
}

#[test]
fn run_glibc_pie_twice() {
    // Release kernel tests run on a 4 KiB system stack. ELF and VFS
    // preparation need room for both the loader and exception frames.
    let done = Arc::new(AtomicUsize::new(0));
    let completed = done.clone();
    let cleanup = DeferredCleanup::new(move || {
        completed.store(1, Ordering::Release);
        let _result = sync::atomic_wake(&completed, usize::MAX);
    })
    .unwrap();
    let test_thread = Builder::new(Entry::Closure(Box::new(run_fixture)))
        .set_stack(Stack::from_size(16 * 1024).unwrap())
        .build();
    test_thread.lock().set_deferred_cleanup(cleanup);
    scheduler::queue_ready_thread(thread::IDLE, test_thread).unwrap();
    while done.load(Ordering::Acquire) == 0 {
        let _result = sync::atomic_wait(&done, 0, Tick::MAX);
    }
}

fn run_fixture() {
    let result = vfs::syscalls::mkdir(c"/lib".as_ptr(), 0o755);
    assert!(result == 0 || result == -libc::EEXIST);
    stage(c"/lib/ld-linux-aarch64.so.1", "ld-linux-aarch64.so.1");
    stage(c"/lib/libc.so.6", "libc.so.6");
    stage(c"/glibc-hello", "glibc-hello");
    let request = RunRequest {
        stack_size: 64 * 1024,
        ..RunRequest::default()
    };
    for _ in 0..2 {
        // SAFETY: all three staged fixtures are built locally from trusted sources.
        let status = unsafe { run_linux_from_path(c"/glibc-hello", &request, &[0xa5; 16]) };
        assert_eq!(status.expect("run glibc PIE"), 42);
    }
    semihosting::println!("glibc smoke test passed twice");
}
