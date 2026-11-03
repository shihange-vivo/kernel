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

//! Per-application runtime context.
//!
//! Every dynamic application gets one [`LibcApplicationContext`], built by the
//! dynamic entry from the pinned
//! [`blueos_header::application::BlueOsApplicationStartInfo`] and installed on
//! the main thread's TCB. It owns the state that must stay application-local
//! rather than shared across two concurrently-running applications: the `auxv`
//! table and the atexit list. The kernel's
//! start storage already pins the *bytes* behind `info` for the application
//! lifetime; the context additionally owns its own copy of the auxv entries so a
//! future larger `struct_size` (appended fields) can never dangle.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use spin::RwLock;

use blueos_header::application::BlueOsAuxvEntry;
#[cfg(any(dynamic_image, test))]
use blueos_header::application::{BlueOsApplicationStartInfo, APPLICATION_START_INFO_ABI_VERSION};

/// An application-owned destructor registered through `atexit`.
pub type AtExitEntry = extern "C" fn();

/// The application-local runtime state.
pub struct LibcApplicationContext {
    auxv: Box<[BlueOsAuxvEntry]>,
    atexit: RwLock<Vec<AtExitEntry>>,
}

impl LibcApplicationContext {
    /// Copy an auxiliary vector into application-owned storage.
    /// Returns `None` if reserving the copy fails. An empty slice is valid,
    /// and the source need not outlive the returned context.
    pub fn new(entries: &[BlueOsAuxvEntry]) -> Option<Arc<Self>> {
        let mut auxv = Vec::new();
        auxv.try_reserve_exact(entries.len()).ok()?;
        auxv.extend_from_slice(entries);

        Some(Arc::new(Self {
            auxv: auxv.into_boxed_slice(),
            atexit: RwLock::new(Vec::new()),
        }))
    }

    /// Decode the startup ABI at the trusted dynamic-entry boundary.
    /// Rejects unsupported prefixes and invalid pointer/range shapes; an
    /// empty auxv never dereferences its pointer.
    ///
    /// # Safety
    /// If the non-empty auxv passes the checks below, the caller must ensure
    /// it denotes initialized, readable entries in one allocation, without
    /// concurrent mutation, for this call. Pointer-shape checks cannot prove
    /// that the memory is accessible or still alive.
    // SAFETY: The startup caller supplies the readable auxv allocation. The
    // checks below enforce the remaining slice preconditions before copying.
    #[cfg(any(dynamic_image, test))]
    pub(crate) unsafe fn from_start_info(info: &BlueOsApplicationStartInfo) -> Option<Arc<Self>> {
        if info.abi_version != APPLICATION_START_INFO_ABI_VERSION {
            return None;
        }
        if info.struct_size < core::mem::size_of::<BlueOsApplicationStartInfo>() as u32 {
            return None;
        }

        if info.auxv_count == 0 {
            return Self::new(&[]);
        }
        if info.auxv.is_null() || !info.auxv.is_aligned() {
            return None;
        }
        let byte_len = info
            .auxv_count
            .checked_mul(core::mem::size_of::<BlueOsAuxvEntry>())?;
        if byte_len > isize::MAX as usize {
            return None;
        }
        (info.auxv as usize).checked_add(byte_len)?;

        // SAFETY: The checks establish a non-null, aligned, non-wrapping
        // range within the slice size limit. The caller guarantees readable,
        // initialized entries in one live allocation throughout the copy.
        let entries = unsafe { core::slice::from_raw_parts(info.auxv, info.auxv_count) };
        Self::new(entries)
    }

    /// Look up an auxiliary-vector entry by key. Returns `0` when the
    /// key is absent, matching `getauxval`'s not-found convention.
    pub fn getauxval(&self, key: usize) -> usize {
        self.auxv
            .iter()
            .find(|entry| entry.key == key)
            .map_or(0, |entry| entry.value)
    }

    /// `getauxval` with the current thread's context; on a miss or when the
    /// thread has no application context, returns `0` and sets `errno` to
    /// `ENOENT` per the POSIX convention.
    #[inline]
    pub fn get_or_errno(key: usize) -> usize {
        match Self::get(key) {
            Some(value) => value,
            None => {
                crate::errno::ERRNO.set(libc::ENOENT);
                0
            }
        }
    }

    /// `getauxval` against the current thread's context without touching
    /// `errno`. Returns `None` when the key is absent *or* the calling thread
    /// has no application context (static path threads).
    #[inline]
    pub fn get(key: usize) -> Option<usize> {
        crate::pthread::get_my_context().map(|context| context.getauxval(key))
    }

    /// `atexit` against the current thread's application context.
    /// Returns `0` on success, `ENOMEM` when the registration cannot reserve
    /// space, and `ENOENT` when the thread has no application context.
    #[inline]
    pub fn atexit(function: AtExitEntry) -> core::ffi::c_int {
        let Some(context) = crate::pthread::get_my_context() else {
            return libc::ENOENT;
        };
        if context.register_atexit(function) {
            0
        } else {
            libc::ENOMEM
        }
    }

    /// Register an application-owned destructor. Returns `false`
    /// on allocation failure; destructors run in reverse registration order.
    pub fn register_atexit(&self, function: AtExitEntry) -> bool {
        let mut list = self.atexit.write();
        if list.try_reserve(1).is_err() {
            return false;
        }
        list.push(function);
        true
    }

    /// Run every registered destructor in reverse order, including callbacks
    /// registered by a running destructor before older pending callbacks.
    pub fn run_atexit(&self) {
        loop {
            let function = {
                let mut list = self.atexit.write();
                list.pop()
            };
            let Some(function) = function else {
                break;
            };
            // A callback may call `atexit` and acquire this same write lock.
            // The guard above must be released before invoking it.
            function();
        }
    }
}

/// POSIX `getauxval(key)` against the current thread's application context.
/// Returns `0` (and sets `errno` to `ENOENT`) when the key is absent or
/// the calling thread has no application context.
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn getauxval(key: core::ffi::c_ulong) -> core::ffi::c_ulong {
    LibcApplicationContext::get_or_errno(key as usize) as core::ffi::c_ulong
}

/// POSIX `atexit(function)` against the current thread's application context.
/// Returns `0` on success, or a positive errno on failure.
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn atexit(function: AtExitEntry) -> core::ffi::c_int {
    LibcApplicationContext::atexit(function)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_header::application::{BlueOsFunctionPlan, FUNCTION_PLAN_ABI_VERSION};
    use blueos_test_macro::test;
    use core::{mem::size_of, ptr};

    fn empty_start_info() -> BlueOsApplicationStartInfo {
        let plan = BlueOsFunctionPlan {
            abi_version: FUNCTION_PLAN_ABI_VERSION,
            struct_size: size_of::<BlueOsFunctionPlan>() as u32,
            entries: ptr::null(),
            count: 0,
        };
        BlueOsApplicationStartInfo {
            abi_version: APPLICATION_START_INFO_ABI_VERSION,
            struct_size: size_of::<BlueOsApplicationStartInfo>() as u32,
            argc: 0,
            argv: ptr::null(),
            envc: 0,
            envp: ptr::null(),
            auxv: ptr::null(),
            auxv_count: 0,
            init_plan: plan,
            fini_plan: plan,
        }
    }

    #[test]
    fn context_accepts_an_empty_auxv_slice() {
        let context = LibcApplicationContext::new(&[]).expect("empty context");
        assert_eq!(context.getauxval(42), 0);
    }

    #[test]
    fn context_owns_its_auxv_copy() {
        let context = {
            let entries = [BlueOsAuxvEntry { key: 42, value: 99 }];
            LibcApplicationContext::new(&entries).expect("context")
        };
        assert_eq!(context.getauxval(42), 99);
        assert_eq!(context.getauxval(43), 0);
    }

    #[test]
    fn startup_accepts_empty_auxv_without_accessing_its_pointer() {
        let mut info = empty_start_info();
        let misaligned = ptr::dangling::<u8>().cast::<BlueOsAuxvEntry>();
        for pointer in [ptr::null(), misaligned] {
            info.auxv = pointer;
            // SAFETY: A zero count needs no readable auxv allocation.
            let context = unsafe { LibcApplicationContext::from_start_info(&info) }
                .expect("empty startup auxv");
            assert_eq!(context.getauxval(42), 0);
        }
    }

    #[test]
    fn startup_rejects_null_or_misaligned_nonempty_auxv() {
        let mut info = empty_start_info();
        info.auxv_count = 1;
        let misaligned = ptr::dangling::<u8>().cast::<BlueOsAuxvEntry>();
        for pointer in [ptr::null(), misaligned] {
            info.auxv = pointer;
            // SAFETY: These pointer shapes are rejected before dereferencing.
            assert!(unsafe { LibcApplicationContext::from_start_info(&info) }.is_none());
        }
    }

    #[test]
    fn startup_rejects_invalid_auxv_extents() {
        let mut info = empty_start_info();
        let entries = [BlueOsAuxvEntry { key: 42, value: 99 }];
        info.auxv = entries.as_ptr();
        let over_slice_limit = (isize::MAX as usize / size_of::<BlueOsAuxvEntry>())
            .checked_add(1)
            .expect("count within usize");
        for count in [usize::MAX, over_slice_limit] {
            info.auxv_count = count;
            // SAFETY: Invalid byte lengths are rejected before any auxv read.
            assert!(unsafe { LibcApplicationContext::from_start_info(&info) }.is_none());
        }
        let alignment = core::mem::align_of::<BlueOsAuxvEntry>();
        info.auxv = (usize::MAX & !alignment.saturating_sub(1)) as *const BlueOsAuxvEntry;
        info.auxv_count = 1;
        // SAFETY: The wrapping address range is rejected before any auxv read.
        assert!(unsafe { LibcApplicationContext::from_start_info(&info) }.is_none());
    }

    #[test]
    fn startup_validates_the_versioned_prefix() {
        let mut info = empty_start_info();
        info.abi_version = u32::MAX;
        // SAFETY: No auxv storage is needed for this empty table.
        assert!(unsafe { LibcApplicationContext::from_start_info(&info) }.is_none());
        info.abi_version = APPLICATION_START_INFO_ABI_VERSION;
        info.struct_size = 0;
        // SAFETY: No auxv storage is needed for this empty table.
        assert!(unsafe { LibcApplicationContext::from_start_info(&info) }.is_none());
        info.struct_size = (size_of::<BlueOsApplicationStartInfo>() as u32).saturating_add(8);
        // SAFETY: Only the initialized v1 prefix is read; the auxv is empty.
        assert!(unsafe { LibcApplicationContext::from_start_info(&info) }.is_some());
    }

    #[test]
    fn startup_copies_a_valid_auxv_before_its_source_is_dropped() {
        let context = {
            let entries = [BlueOsAuxvEntry { key: 42, value: 99 }];
            let mut info = empty_start_info();
            info.auxv = entries.as_ptr();
            info.auxv_count = entries.len();
            // SAFETY: `entries` is initialized and immutable for this call.
            unsafe { LibcApplicationContext::from_start_info(&info) }.expect("startup context")
        };
        assert_eq!(context.getauxval(42), 99);
    }
}
