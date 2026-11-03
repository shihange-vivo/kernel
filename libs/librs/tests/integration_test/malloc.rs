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

//! Allocation ABI regressions, including direct callers that bypass libc.

use blueos_header::syscalls::NR::AllocMem;
use blueos_scal::bk_syscall;
use blueos_test_macro::test;
use core::{cell::Cell, ffi::c_void, mem::size_of, ptr};
use libc::{EINVAL, ENOMEM};
use librs::{
    errno::ERRNO,
    stdlib::malloc::{free, memalign, posix_memalign},
};

#[test]
fn posix_memalign_rejects_invalid_arguments_without_changing_output_or_errno() {
    let mut byte = 0u8;
    let sentinel = ptr::addr_of_mut!(byte).cast::<c_void>();
    let saved_errno = ERRNO.replace(0);
    for alignment in [0, 3, size_of::<*mut c_void>() / 2] {
        let mut output = sentinel;
        // SAFETY: `output` is writable pointer storage. Failure must not
        // replace it, and the sentinel is never treated as an allocation.
        let rc = unsafe { posix_memalign(&mut output, alignment, 16) };
        assert_eq!(rc, EINVAL);
        assert_eq!(output, sentinel);
        assert_eq!(ERRNO.get(), 0);
    }
    // SAFETY: The implementation explicitly rejects null output storage.
    assert_eq!(unsafe { posix_memalign(ptr::null_mut(), 16, 16) }, EINVAL);
    assert_eq!(ERRNO.get(), 0);
    ERRNO.set(saved_errno);
}

#[test]
fn memalign_rejects_invalid_alignment_with_einval() {
    let saved_errno = ERRNO.get();
    for alignment in [0, 3, 6] {
        ERRNO.set(0);
        // SAFETY: The invalid request must return null without allocating.
        let output = unsafe { memalign(alignment, 16) };
        assert!(output.is_null());
        assert_eq!(ERRNO.get(), EINVAL);
    }
    ERRNO.set(saved_errno);
}

#[test]
fn aligned_allocations_support_small_and_large_alignment() {
    for alignment in [1, 2, 4, 8, 16, 64] {
        // SAFETY: The returned allocation is checked before accessing its
        // 16-byte range, and is freed exactly once after the checks.
        unsafe {
            let output = memalign(alignment, 16).cast::<u8>();
            assert!(!output.is_null());
            assert_eq!(output as usize % alignment, 0);
            output.write_bytes(0x5a, 16);
            assert_eq!(output.add(15).read(), 0x5a);
            free(output.cast());
        }
    }
    for alignment in [size_of::<*mut c_void>(), 64] {
        let mut output = ptr::null_mut();
        // SAFETY: `output` is writable storage; a successful allocation is
        // checked and released once through the matching libc entry point.
        unsafe {
            assert_eq!(posix_memalign(&mut output, alignment, 16), 0);
            assert!(!output.is_null());
            assert_eq!(output as usize % alignment, 0);
            free(output);
        }
    }
}

#[test]
fn oversized_allocations_fail_without_overwriting_output() {
    let mut byte = 0u8;
    let sentinel = ptr::addr_of_mut!(byte).cast::<c_void>();
    let mut output = sentinel;
    let saved_errno = ERRNO.replace(0);
    // SAFETY: The output slot is valid. The impossible layout must fail
    // before allocation and leave the sentinel untouched.
    let rc = unsafe { posix_memalign(&mut output, size_of::<*mut c_void>(), usize::MAX) };
    assert_eq!(rc, ENOMEM);
    assert_eq!(output, sentinel);
    assert_eq!(ERRNO.get(), 0);
    // SAFETY: The impossible size must return null without allocating.
    assert!(unsafe { memalign(64, usize::MAX) }.is_null());
    assert_eq!(ERRNO.get(), ENOMEM);
    ERRNO.set(saved_errno);
}

#[test]
fn allocation_syscall_rejects_invalid_layouts_without_panicking() {
    let mut byte = 0u8;
    let sentinel = ptr::addr_of_mut!(byte).cast::<c_void>();
    for (size, alignment) in [(16, 0), (16, 3), (usize::MAX, size_of::<*mut c_void>())] {
        let mut output = sentinel;
        assert_ne!(
            bk_syscall!(AllocMem, &mut output as *mut *mut c_void, size, alignment),
            0
        );
        assert_eq!(output, sentinel);
    }
}

#[thread_local]
static BYTE_TLS: Cell<u8> = Cell::new(0);

#[test]
fn byte_aligned_tls_remains_allocatable() {
    BYTE_TLS.set(42);
    assert_eq!(BYTE_TLS.get(), 42);
}
