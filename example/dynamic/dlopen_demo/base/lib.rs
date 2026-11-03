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
static mut COUNT: usize = 0;
extern "C" fn init() {
    extern "C" {
        fn dlopen(name: *const core::ffi::c_char, flags: i32) -> *mut core::ffi::c_void;
        fn dlsym(
            handle: *mut core::ffi::c_void,
            name: *const core::ffi::c_char,
        ) -> *mut core::ffi::c_void;
        fn dlclose(handle: *mut core::ffi::c_void) -> i32;
        fn dlerror() -> *mut core::ffi::c_char;
        fn write(fd: i32, data: *const u8, len: usize) -> isize;
    }
    // A new system DSO depending on this still-Initializing libc cannot
    // become registry-Ready yet. Its completed constructor is rolled back.
    // SAFETY: this static terminated filename outlives the call; the mapped
    // startup libc supplies dlopen and validates the scalar flags.
    let system = unsafe { dlopen(b"libscope_sys.so\0".as_ptr().cast(), 2) };
    if system.is_null() {
        // SAFETY: dlerror takes no pointer inputs; only its NULL status is read.
        assert!(!unsafe { dlerror() }.is_null());
        // SAFETY: a second query consumes no borrowed pointer from the first.
        assert!(unsafe { dlerror() }.is_null());
        let message = b"DLOPEN_STARTUP_ROLLBACK\n";
        // SAFETY: message is immutable for exactly message.len() readable
        // bytes, and write retains no pointer after returning.
        unsafe { write(1, message.as_ptr(), message.len()) };
    } else {
        // SAFETY: the successful open returned this owned opaque token;
        // closing it does not dereference the token as an application pointer.
        assert_eq!(unsafe { dlclose(system) }, 0);
    }
    // The startup libc batch is still Initializing; borrow it while opening
    // the dependency instead of waiting for this constructor to finish.
    // SAFETY: the static C filename is readable through its terminator.
    let handle = unsafe { dlopen(b"libdl_dep.so.1\0".as_ptr().cast(), 2) };
    assert!(!handle.is_null());
    // SAFETY: handle is open and the static symbol name is NUL-terminated.
    let function = unsafe { dlsym(handle, b"dl_dep_value\0".as_ptr().cast()) };
    assert!(!function.is_null());
    // SAFETY: this known fixture export is extern C fn() -> usize, and its
    // successful handle stays open until after the call completes.
    let function: extern "C" fn() -> usize = unsafe { core::mem::transmute(function) };
    assert_eq!(function(), 41);
    // SAFETY: handle is the still-owned token from the open above.
    assert_eq!(unsafe { dlclose(handle) }, 0);
    // SAFETY: this private instance's constructor runs once before its main
    // thread observes COUNT; the fixture has no concurrent writer or reader.
    unsafe { COUNT += 1 };
}
extern "C" fn fini() {
    extern "C" {
        fn write(fd: i32, data: *const u8, len: usize) -> isize;
    }
    let message = b"DLOPEN_BASE_FINI\n";
    // SAFETY: this immutable message slice stays readable through the write;
    // libc is a retained provider through this DSO's fini plan.
    unsafe {
        write(1, message.as_ptr(), message.len());
    }
}
#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;
#[used]
#[link_section = ".fini_array"]
static FINI: extern "C" fn() = fini;
#[no_mangle]
pub extern "C" fn dl_base_count() -> usize {
    // SAFETY: this fixture reads only after its one constructor completed;
    // its private COUNT is never subsequently written or shared with a writer.
    unsafe { COUNT }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    extern "C" {
        fn write(fd: i32, data: *const u8, len: usize) -> isize;
    }
    let message = b"DLOPEN_FAIL startup constructor\n";
    // SAFETY: the live static bytes cover message.len() and libc is retained
    // while reporting this constructor failure; write uses them synchronously.
    unsafe {
        write(1, message.as_ptr(), message.len());
    }
    loop {}
}
