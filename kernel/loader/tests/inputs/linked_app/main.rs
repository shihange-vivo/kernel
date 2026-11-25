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

#![no_main]
#![no_std]

use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::{c_char, c_int, CStr},
    ptr,
};
use librs::dlfcn::{dlclose, dlerror, dlopen, dlsym, RTLD_GLOBAL, RTLD_LAZY, RTLD_NOW};

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut memory = ptr::null_mut();
        let result = unsafe {
            librs::stdlib::malloc::posix_memalign(
                &raw mut memory,
                layout.align().max(size_of::<usize>()),
                layout.size(),
            )
        };
        if result == 0 {
            memory.cast()
        } else {
            ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, memory: *mut u8, _layout: Layout) {
        unsafe { librs::stdlib::malloc::free(memory.cast()) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

unsafe extern "C" {
    fn linked_value() -> c_int;
    static linked_data: c_int;
}

#[unsafe(no_mangle)]
pub extern "C" fn linked_choice() -> c_int {
    2
}

#[unsafe(no_mangle)]
pub extern "C" fn record_event(event: u8) {
    // The DSO calls back into the root's libc after startup initialized it.
    let mode = unsafe { librs::stdlib::getenv(c"LINK_TEST".as_ptr()) };
    assert!(!mode.is_null());
    assert_eq!(librs::unistd::write(1, &raw const event, 1), 1);
    // SAFETY: getenv returned a live NUL-terminated environment string.
    let mode = unsafe { CStr::from_ptr(mode) };
    if (event == b'D' && mode == c"abort") || (event == b'L' && mode == c"runtime-abort") {
        unsafe { librs::startup::exit(19) };
    }
    if event == b'L' && mode == c"runtime" {
        assert!(unsafe { dlopen(c"linked-plugin.so".as_ptr(), RTLD_NOW) }.is_null());
        expect_dlerror(c"the thread group is loading or finalizing a library");
    }
}

type Init = extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

extern "C" fn preinit(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    record_event(b'P');
}

extern "C" fn init(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    record_event(b'I');
}

extern "C" fn fini() {
    record_event(b'F');
}

#[used]
#[unsafe(link_section = ".preinit_array")]
static PREINIT: Init = preinit;

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: Init = init;

#[used]
#[unsafe(link_section = ".fini_array")]
static FINI: extern "C" fn() = fini;

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    let mode = unsafe { librs::stdlib::getenv(c"LINK_TEST".as_ptr()) };
    // SAFETY: a non-null getenv result points to the current environment string.
    let mode = if mode.is_null() {
        c""
    } else {
        unsafe { CStr::from_ptr(mode) }
    };
    if mode == c"runtime" || mode == c"runtime-abort" || mode == c"runtime-small-stack" {
        assert_eq!(unsafe { linked_data }, 21);
        record_event(b'M');
        if mode == c"runtime-small-stack" {
            assert!(unsafe { dlopen(c"linked-plugin.so".as_ptr(), RTLD_NOW) }.is_null());
            expect_dlerror(c"insufficient memory or stack for dynamic loading");
            // Reusing a startup dependency only needs to create a new handle.
            let existing = unsafe { dlopen(c"liblinked_test_dso.so".as_ptr(), RTLD_NOW) };
            assert!(!existing.is_null());
            assert_eq!(unsafe { dlclose(existing) }, 0);
            assert_eq!(unsafe { linked_data }, 21);
            return 21;
        }
        // SAFETY: all strings and handles are supplied to the native librs ABI.
        unsafe { exercise_dlfcn() };
        return unsafe { linked_value() };
    }
    let with_plugin = mode == c"plugin";
    assert_eq!(unsafe { linked_data }, if with_plugin { 22 } else { 21 });
    record_event(b'M');
    unsafe { linked_value() }
}

fn expect_dlerror(expected: &CStr) {
    let error = dlerror();
    assert!(!error.is_null());
    // SAFETY: the libc keeps its diagnostic string live after dlerror().
    assert_eq!(unsafe { CStr::from_ptr(error) }, expected);
    assert!(dlerror().is_null());
}

unsafe fn exercise_dlfcn() {
    unsafe {
        let main = dlopen(core::ptr::null(), RTLD_NOW);
        assert!(!main.is_null());
        assert_eq!(
            dlsym(main, c"linked_choice".as_ptr()).addr(),
            linked_choice as *const () as usize
        );
        assert_eq!(dlclose(main), 0);
        assert!(dlopen(c"linked-plugin.so".as_ptr(), RTLD_NOW | RTLD_GLOBAL).is_null());
        expect_dlerror(c"dlopen: global visibility is not supported");
        assert!(dlopen(c"/absent-plugin.so".as_ptr(), RTLD_NOW).is_null());
        expect_dlerror(c"cannot read the library or its dependencies");

        let first = dlopen(c"linked-plugin.so".as_ptr(), RTLD_NOW);
        assert!(!first.is_null());
        assert_eq!(linked_data, 22);
        let second = dlopen(c"/linked-fixtures/./linked-plugin.so".as_ptr(), RTLD_LAZY);
        assert!(!second.is_null());
        let data = dlsym(first, c"linked_data".as_ptr()).cast::<c_int>();
        assert!(!data.is_null());
        assert_eq!(data.read(), 22);
        assert_eq!(
            dlsym(first, c"record_event".as_ptr()),
            core::ptr::null_mut()
        );
        expect_dlerror(c"dynamic symbol not found");
        assert_eq!(dlclose(first), 0);
        assert!(dlsym(first, c"plugin_data".as_ptr()).is_null());
        expect_dlerror(c"invalid dynamic library handle");
        assert_eq!(dlsym(second, c"linked_data".as_ptr()).cast::<c_int>(), data);
        assert_eq!(dlclose(second), 0);

        let reopened = dlopen(c"linked-plugin.so".as_ptr(), RTLD_NOW);
        assert!(!reopened.is_null());
        assert_eq!(linked_data, 22);
        assert_eq!(dlclose(reopened), 0);
        assert!(dlerror().is_null());
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { librs::startup::exit(127) }
}
