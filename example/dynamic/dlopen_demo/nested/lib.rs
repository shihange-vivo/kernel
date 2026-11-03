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

#![no_std]
use core::ffi::{c_char, c_void};
extern "C" {
    fn dlopen(name: *const c_char, flags: i32) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> i32;
    fn dl_event(tag: usize);
}
static mut VALUE: usize = 0;
extern "C" fn load_child() {
    // SAFETY: the static terminated filename remains live through dlopen;
    // libc is mapped during this nested constructor/destructor call.
    let handle = unsafe { dlopen(b"libdl_dep.so.1\0".as_ptr().cast(), 2) };
    assert!(!handle.is_null());
    // SAFETY: handle is open and the static export name is terminated.
    let pointer = unsafe { dlsym(handle, b"dl_dep_value\0".as_ptr().cast()) };
    assert!(!pointer.is_null());
    // SAFETY: the known export is extern C fn() -> usize and the child handle
    // stays open through the call, pinning code and all its providers.
    let function: extern "C" fn() -> usize = unsafe { core::mem::transmute(pointer) };
    let value = function();
    // SAFETY: this private instance's lifecycle callbacks are serialized;
    // the fixture reads VALUE after init and stops readers before fini.
    unsafe { VALUE = value };
    // SAFETY: handle is the owned token from this call's successful open.
    assert_eq!(unsafe { dlclose(handle) }, 0);
}
extern "C" fn init() {
    load_child();
    // SAFETY: the root supplies the matching extern C fn(usize) callback and
    // remains mapped throughout this dependency's init plan.
    unsafe {
        dl_event(4);
    }
}
extern "C" fn fini() {
    load_child();
    // SAFETY: the pinned root's C callback remains callable until fini ends.
    unsafe {
        dl_event(5);
    }
}
#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;
#[used]
#[link_section = ".fini_array"]
static FINI: extern "C" fn() = fini;
#[no_mangle]
pub extern "C" fn dl_nested_value() -> usize {
    // SAFETY: the fixture reads after init, before serialized finalization;
    // no lifecycle callback writes VALUE concurrently with this export.
    unsafe { VALUE }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    extern "C" {
        fn write(fd: i32, data: *const u8, len: usize) -> isize;
    }
    let message = b"DLOPEN_FAIL nested\n";
    // SAFETY: the static slice is readable for its length through write, and
    // the libc provider remains mapped during lifecycle error reporting.
    unsafe {
        write(1, message.as_ptr(), message.len());
    }
    loop {}
}
