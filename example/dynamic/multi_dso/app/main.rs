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

//! The multi_dso root application: calls through the private
//! `foo`/`bar` DSOs into the shared `common` diamond node and prints the
//! results through the system libc, proving the whole private closure got
//! linked and relocated.

#![no_std]
#![no_main]
#![feature(c_variadic)]

use core::ffi::{c_char, c_int};

extern "C" {
    fn foo_value() -> i32;
    fn bar_value() -> i32;
    fn printf(format: *const c_char, ...) -> c_int;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn main(
    _argc: c_int,
    _argv: *const *const c_char,
    _envp: *const *const c_char,
) -> c_int {
    // SAFETY: foo's export matches extern C fn() -> i32; the application's
    // receipt pins foo and its transitive providers until application exit.
    let foo = unsafe { foo_value() }; // common(40) + 2
                                      // SAFETY: bar's export has the same C signature and is pinned by the same
                                      // application-owned closure for this call.
    let bar = unsafe { bar_value() }; // common(40) * 2
                                      // SAFETY: the static NUL-terminated format expects two C ints; both
                                      // arguments are i32 and libc remains pinned for the application.
    unsafe {
        printf(
            b"multi: foo=%d bar=%d\n\0".as_ptr() as *const c_char,
            foo,
            bar,
        );
    }
    (foo == 42 && bar == 80) as c_int
}
