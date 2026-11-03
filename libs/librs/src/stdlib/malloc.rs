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

// FIXME: We are using kernel's allocator currently. Formally, we should use mmap to implement malloc.
use crate::errno::ERRNO;
use blueos_header::syscalls::NR::{AllocMem, FreeMem, ReallocMem, Write};
use blueos_scal::bk_syscall;
use libc::{c_int, c_void, size_t, EINVAL, ENOMEM};

/// Allocate with a power-of-two alignment that is a multiple of pointer size.
/// Failure leaves the output pointer and `errno` unchanged.
///
/// # Safety
/// A non-null ptr must name one aligned, exclusively writable pointer slot
/// that stays live throughout the call. NULL is rejected. On success, the
/// returned block is uninitialized and owned by the caller until freed.
// SAFETY: the caller retains the exclusive output slot, and the synchronous
// allocation syscall writes one pointer there only after validating the layout.
#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    ptr: *mut *mut c_void,
    align: size_t,
    size: size_t,
) -> c_int {
    if ptr.is_null() || !align.is_power_of_two() || align < core::mem::size_of::<*mut c_void>() {
        return EINVAL;
    }
    let rc = bk_syscall!(AllocMem, ptr, size, align);
    if rc != 0 {
        return ENOMEM;
    }
    0
}

/// Release a block obtained from this allocator family; NULL is a no-op.
///
/// # Safety
/// A non-null ptr must be the base of a live allocation from this allocator.
/// The caller must relinquish it exactly once, with no concurrent access or
/// later use through any pointer or reference into the released block.
// SAFETY: the caller transfers a live allocation base; FreeMem recovers its
// layout in the kernel and performs the sole release, accepting NULL as a no-op.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    bk_syscall!(FreeMem, ptr);
}

/// Allocate size uninitialized bytes, returning NULL on failure.
///
/// # Safety
/// The call itself imposes no caller memory requirements. A non-null result
/// may only be accessed within size bytes and must be initialized before read;
/// its ownership must eventually be transferred or released through free.
// SAFETY: allocation only writes to the local pointer slot. Ownership of any
// new block is returned without constructing a reference to its contents.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let mut ptr: *mut c_void = core::ptr::null_mut();
    // SAFETY: ptr is an aligned, exclusive local output slot that outlives
    // the synchronous call; the requested alignment is validated by the callee.
    let rc = unsafe {
        posix_memalign(
            &mut ptr as *mut *mut c_void,
            core::mem::size_of::<usize>(),
            size,
        )
    };
    if rc != 0 {
        return core::ptr::null_mut();
    }
    ptr
}

/// Resize an allocation, preserving its contents up to the smaller of the two
/// sizes.
///
/// The kernel performs the resize: only it knows the old block's size, and
/// reimplementing that here would mean either tracking sizes in `malloc` (which
/// changes the pointer every existing caller sees) or copying a length the
/// caller cannot supply.
///
/// # Safety
/// ptr must be NULL or the base of a live block from this allocator family,
/// reserved exclusively for this resize. A successful nonzero resize ends the
/// old allocation's lifetime; failure preserves it. A zero size frees it.
/// No access through old pointers or references may outlive that allocation.
// SAFETY: the caller supplies an exclusively owned live block or NULL. The
// kernel owns its size metadata; moved is an exclusive local pointer output.
#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    let mut moved: *mut c_void = core::ptr::null_mut();
    // A zero size is the C "free and return null" case, and the kernel handler
    // reports it as failure; free here so the block is not leaked.
    if size == 0 {
        // SAFETY: realloc's contract supplies the same live base and exclusive
        // ownership required by free; NULL is also supported.
        unsafe { free(ptr) };
        return core::ptr::null_mut();
    }
    let rc = bk_syscall!(ReallocMem, &mut moved as *mut *mut c_void, ptr, size);
    if rc != 0 {
        return core::ptr::null_mut();
    }
    moved
}

/// Allocate `count * size` zeroed bytes. `malloc` plus an explicit clear: the
/// kernel's `calloc` is not reachable from here and the zeroing is unambiguous
/// at this level.
///
/// # Safety
/// The call itself imposes no caller memory requirements. A non-null result
/// owns count * size zeroed bytes; accesses must remain within that block and
/// its ownership must eventually be transferred or released through free.
// SAFETY: checked multiplication bounds the allocation, and clearing occurs
// only on a fresh, non-null block before any pointer to it escapes.
#[no_mangle]
pub unsafe extern "C" fn calloc(count: size_t, size: size_t) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        return core::ptr::null_mut();
    };
    // SAFETY: malloc has no caller memory preconditions; total is checked.
    let ptr = unsafe { malloc(total) };
    if !ptr.is_null() {
        // SAFETY: malloc returned a fresh block writable for total bytes;
        // no other reference or pointer has been given access to it yet.
        unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, total) };
    }
    ptr
}

/// Allocate with any nonzero power-of-two alignment, returning null and
/// setting `errno` on failure.
///
/// # Safety
/// The call itself imposes no caller memory requirements. A non-null result
/// owns size uninitialized bytes with at least the requested alignment; use
/// must stay within the block, initialize before read and release it once.
// SAFETY: Allocation itself has no caller memory preconditions. The returned
// block, when non-null, must be accessed within `size` bytes and freed once.
#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: size_t, size: size_t) -> *mut c_void {
    if !alignment.is_power_of_two() {
        ERRNO.set(EINVAL);
        return core::ptr::null_mut();
    }
    // `memalign` accepts smaller alignments than `posix_memalign`. A stronger
    // alignment also satisfies the original request.
    let alignment = alignment.max(core::mem::size_of::<*mut c_void>());
    let mut ptr: *mut c_void = core::ptr::null_mut();
    // SAFETY: `ptr` is writable local storage and outlives the allocation call.
    let rc = unsafe { posix_memalign(&mut ptr as *mut *mut c_void, alignment, size) };
    if rc != 0 {
        ERRNO.set(rc);
        return core::ptr::null_mut();
    }
    ptr
}

/// Terminal landing pad for `-Cpanic=abort`.
///
/// Prints a marker before parking: the DSO has no unwinder, so the only way a
/// failure here is diagnosable under QEMU is for it to say so on stderr before
/// it stops responding.
#[no_mangle]
pub extern "C" fn abort() -> ! {
    const MESSAGE: &[u8] = b"libc: abort()\n";
    bk_syscall!(Write, 2, MESSAGE.as_ptr(), MESSAGE.len());
    loop {
        core::hint::spin_loop();
    }
}
