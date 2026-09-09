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

//! Boot-time system image seeding (C29, §18.1/18.2).
//!
//! The dynamic system image — the hello PIE and `libc.so.1` — is embedded in
//! the kernel binary by the build (`.bk_seed`, see `gen_seed_blob_asm.py`) and
//! copied into the root tmpfs here, under fixed paths. This module only
//! installs bytes into the VFS; [`super::runtime`] separately assembles the
//! loader-facing application service over those paths.

/// The embedded system image (C29 §18.1). The build emits one start/end
/// symbol pair per artifact around an `.incbin` of its bytes.
extern "C" {
    static __bk_seed_hello_start: u8;
    static __bk_seed_hello_end: u8;
    static __bk_seed_shell_start: u8;
    static __bk_seed_shell_end: u8;
    static __bk_seed_libc_start: u8;
    static __bk_seed_libc_end: u8;
    static __bk_seed_scope_sys_start: u8;
    static __bk_seed_scope_sys_end: u8;
}

/// The bytes of one embedded artifact.
///
/// # Safety
/// The symbol pair bounds a `.bk_seed` blob the build emitted from the real
/// artifact; `start <= end` and the range is read-only linker data.
unsafe fn blob(start: &'static u8, end: &'static u8) -> &'static [u8] {
    let begin = start as *const u8;
    let len = (end as *const u8 as usize).wrapping_sub(begin as usize);
    // SAFETY: see the contract above.
    unsafe { core::slice::from_raw_parts(begin, len) }
}

/// Create the parent directories of `path` inside the root tmpfs, best effort
/// (already-exists errors are fine). Only *parents* are created: the last
/// component is the file itself.
fn mkdirs(path: &str) {
    let mut bytes = [0u8; 64];
    let mut prefix_end = 1; // skip the leading '/'
    while prefix_end < path.len() {
        let slash = match path[prefix_end..].find('/') {
            Some(at) => prefix_end + at,
            // The last component is the seeded file, not a directory.
            None => break,
        };
        let dir = &path[..slash];
        debug_assert!(dir.len() < bytes.len(), "seed path too deep");
        bytes[..dir.len()].copy_from_slice(dir.as_bytes());
        bytes[dir.len()] = 0;
        // SAFETY: `bytes` holds a NUL-terminated copy of `dir`.
        let _ = unsafe {
            crate::vfs::syscalls::mkdir(bytes.as_ptr() as *const core::ffi::c_char, 0o755)
        };
        prefix_end = slash + 1;
    }
}

/// Write `bytes` into a fresh VFS file at `path`, replacing any previous
/// content.
fn seed_file(path: &str, bytes: &[u8]) {
    mkdirs(path);
    let mut path_buf = [0u8; 64];
    debug_assert!(path.len() < path_buf.len(), "seed path too long");
    path_buf[..path.len()].copy_from_slice(path.as_bytes());
    path_buf[path.len()] = 0;
    // SAFETY: `path_buf` holds a NUL-terminated copy of `path`; the kernel
    // syscall helpers take raw pointers by contract.
    unsafe {
        let fd = crate::vfs::syscalls::open(
            path_buf.as_ptr() as *const core::ffi::c_char,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            log::warn!("boot seed: open {} failed ({})", path, fd);
            return;
        }
        let written = crate::vfs::syscalls::write(fd, bytes.as_ptr(), bytes.len());
        debug_assert_eq!(written as usize, bytes.len(), "seed write truncated");
        crate::vfs::syscalls::close(fd);
    }
}

/// Install the embedded system image into the root tmpfs.
///
/// Boot calls this after the VFS is initialized and before initializing the
/// dynamic application runtime. Reinstalling replaces the files at the same
/// paths, but normal boot invokes this interface exactly once.
pub fn install() {
    // SAFETY: the `.bk_seed` blobs are emitted by the build for this board.
    seed_file("/apps/hello/app.elf", unsafe {
        blob(&__bk_seed_hello_start, &__bk_seed_hello_end)
    });
    seed_file("/apps/shell/app.elf", unsafe {
        blob(&__bk_seed_shell_start, &__bk_seed_shell_end)
    });
    seed_file("/system/lib/libc.so.1", unsafe {
        blob(&__bk_seed_libc_start, &__bk_seed_libc_end)
    });
    seed_file("/system/lib/libscope_sys.so.1", unsafe {
        blob(&__bk_seed_scope_sys_start, &__bk_seed_scope_sys_end)
    });
    // C30 §6.1: the built-in application packages (root + private DSOs) are
    // seeded from their manifest-listed paths.
    for package in crate::application::package::packages() {
        for entry in core::iter::once(&package.root).chain(package.private_images.iter().copied()) {
            // SAFETY: the catalog's blob pairs bound the same linker-emitted
            // artifact bytes the build embedded for this board.
            if let Some(bytes) = unsafe { crate::application::package::image_blob(entry.path) } {
                seed_file(entry.path, bytes);
            } else {
                log::error!("boot seed: package blob missing for {}", entry.path);
            }
        }
    }
}
