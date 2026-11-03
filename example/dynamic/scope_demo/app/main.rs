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

//! scope corpus root: observes the frozen application scope
//! decisions at runtime and prints the bound values.
//!
//! * `scope_value`/`scope_fn` — libweak's weak definition is discovered
//! before libstrong's strong one; the strong must win the application scope.
//! * `hidden_probe` — libhidden's hidden definition is invisible; the binding
//! must land on libstrong's strong definition.
//! * `hidden_report` — the owner's own access to its hidden symbol.
//! * `protected_report` — the owner's self-first binding, even though this
//! root defines a same-named strong `self_value` earlier in the scope.
//! * `sys_report`/`sys_target` — the root defines `sys_target = 42`, but the
//! freshly loaded system DSO must bind its own `sys_target = 777`.
//! * `weakdata_read` — the resolved value of an undefined weak data
//! reference: the frozen scope binds it to zero (also asserted by the
//! SCOPE_BIND oracle).

#![no_std]
#![no_main]
#![feature(c_variadic)]

use core::{
    ffi::{c_char, c_int},
    sync::atomic::Ordering,
};

mod test_gate;
use test_gate::TestGate;

extern "C" {
    fn printf(format: *const c_char, ...) -> c_int;
    static scope_value: i32;
    fn scope_fn() -> i32;
    static hidden_probe: i32;
    fn hidden_report() -> i32;
    fn protected_report() -> i32;
    fn weakdata_read() -> usize;
    fn sys_report() -> i32;
    fn sys_ctor_count() -> u32;
    fn sys_libc_dependency_probe(value: *const c_char) -> usize;
    fn usleep(usec: u32) -> c_int;
}

/// The root's interposing strong definition (application scope, first).
#[no_mangle]
pub static self_value: i32 = 444;

/// A same-named definition as the system DSO's `sys_target`; the system DSO's
/// own relocation must never bind this one.
#[no_mangle]
pub static sys_target: i32 = 42;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Run the scope fixture, optionally using the kernel test's shared gate.
///
/// # Safety
/// Non-null `argv` must contain `argc` initialized C-string pointers, and each
/// non-null string inspected here must remain readable through its NUL byte.
/// Only the trusted kernel test may supply `--test-gate`: its address must
/// name a live, initialized `AtomicUsize` in the shared flat address space for
/// this whole call, with concurrent access performed through atomic operations.
#[no_mangle]
pub unsafe extern "C" fn main(
    argc: c_int,
    argv: *const *const c_char,
    _envp: *const *const c_char,
) -> c_int {
    // SAFETY: argv storage and C-string lifetimes follow the entry contract.
    match unsafe { test_gate::from_argv(argc, argv) } {
        TestGate::NotRequested => {}
        TestGate::Invalid => {
            unsafe { printf(b"scope: invalid test gate arguments\n\0".as_ptr().cast()) };
            return -1;
        }
        TestGate::Address(ready) => {
            let mut opened = false;
            for _ in 0..30_000 {
                // SAFETY: parsing checked null/alignment; the trusted kernel
                // test guarantees the initialized atomic and its lifetime.
                if unsafe { (*ready).load(Ordering::Acquire) } == 2 {
                    opened = true;
                    break;
                }
                unsafe { usleep(1000) };
            }
            if !opened {
                unsafe { printf(b"scope: concurrent gate timeout\n\0".as_ptr().cast()) };
                return -1;
            }
        }
    }

    // The probe's null case is part of its C ABI contract and must not call
    // strlen. Exercise it in the relocated system DSO on every scope launch.
    if unsafe { sys_libc_dependency_probe(core::ptr::null()) } != usize::MAX {
        unsafe { printf(b"scope: null probe failed\n\0".as_ptr().cast()) };
        return -1;
    }
    unsafe { printf(b"scope: null probe rejected\n\0".as_ptr().cast()) };

    let value = unsafe { scope_value };
    let fn_value = unsafe { scope_fn() };
    let hidden = unsafe { hidden_probe };
    let hidden_owner = unsafe { hidden_report() };
    let protected_owner = unsafe { protected_report() };
    let self_binding = unsafe { core::ptr::read_volatile(&self_value) };
    let sys = unsafe { sys_report() };
    let sys_ctor = unsafe { sys_ctor_count() };
    let sys_local = unsafe { core::ptr::read_volatile(&sys_target) };
    let weakdata = unsafe { weakdata_read() };

    let ok = value == 111
        && fn_value == 1110
        && hidden == 555
        && hidden_owner == 999
        && protected_owner == 333
        && self_binding == 444
        && sys == 777
        && sys_local == 42
        && sys_ctor == 1
        && weakdata == 0;

    unsafe {
        printf(
            b"scope: value=%d fn=%d hidden=%d hidden_report=%d protected=%d self=%d sys=%d sys_target=%d sys_ctor=%d weakdata=%d\n\0"
                .as_ptr() as *const c_char,
            value,
            fn_value,
            hidden,
            hidden_owner,
            protected_owner,
            self_binding,
            sys,
            sys_local,
            sys_ctor as c_int,
            weakdata as c_int,
        );
    }
    ok as c_int
}
