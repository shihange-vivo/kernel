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
    if event == b'D' && unsafe { CStr::from_ptr(mode) } == c"abort" {
        unsafe { librs::startup::exit(19) };
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
    assert_eq!(unsafe { linked_data }, 21);
    record_event(b'M');
    unsafe { linked_value() }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { librs::startup::exit(127) }
}
