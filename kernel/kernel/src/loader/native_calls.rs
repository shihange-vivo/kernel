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

//! Ordinary calls between the flat ELF runtime and the trusted host loader.

use blueos_header::startup::DynamicLinker;

pub(super) static DYNAMIC_LINKER: DynamicLinker = DynamicLinker {
    open: platform::open,
    symbol: platform::symbol,
    close: platform::close,
    finalize: platform::finalize,
};

pub(super) use platform::{invoke_finalizer, invoke_initializer};

#[cfg(target_arch = "aarch64")]
mod platform {
    use super::super::linker;
    use core::{
        ffi::{c_char, c_int},
        mem,
    };

    pub(super) unsafe extern "C" fn open(path: *const u8, len: usize) -> isize {
        // SAFETY: the caller supplies the path under the native ABI contract.
        unsafe { linker::open(path, len, 0) }
    }

    pub(super) use linker::symbol;

    pub(super) unsafe extern "C" fn close(handle: usize) -> isize {
        linker::close(handle)
    }

    pub(super) unsafe extern "C" fn finalize() -> isize {
        linker::finalize(0)
    }

    pub(in crate::loader) unsafe fn invoke_initializer(
        address: usize,
        _app_gp: usize,
        [argc, argv, envp]: [usize; 3],
    ) {
        // SAFETY: the loader validated the native entry and retains its mapping.
        let init: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) =
            unsafe { mem::transmute(address) };
        unsafe {
            init(
                argc as c_int,
                argv as *mut *mut c_char,
                envp as *mut *mut c_char,
            )
        };
    }

    pub(in crate::loader) unsafe fn invoke_finalizer(address: usize, _app_gp: usize) {
        // SAFETY: the exiting group still owns the validated finalizer.
        let fini: unsafe extern "C" fn() = unsafe { mem::transmute(address) };
        unsafe { fini() };
    }
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
mod platform {
    use super::super::linker;

    // Each code image may use a different global pointer. Save it across the
    // call. A non-returning application callback retires the thread with its
    // application gp in place. No resources are owned by the assembly frame.
    macro_rules! call_with_saved_gp {
        ($($instructions:literal),+; $($operands:tt)*) => {
            core::arch::naked_asm!(
                "addi sp, sp, -16",
                ".if {word_bytes} == 8",
                "sd ra, 0(sp)",
                "sd gp, 8(sp)",
                ".else",
                "sw ra, 0(sp)",
                "sw gp, 8(sp)",
                ".endif",
                $($instructions,)+
                ".if {word_bytes} == 8",
                "ld gp, 8(sp)",
                "ld ra, 0(sp)",
                ".else",
                "lw gp, 8(sp)",
                "lw ra, 0(sp)",
                ".endif",
                "addi sp, sp, 16",
                "ret",
                word_bytes = const core::mem::size_of::<usize>(),
                $($operands)*
            )
        };
    }

    macro_rules! kernel_entry {
        ($name:ident($($arg:ident: $ty:ty),*), $target:path, $application_gp:literal) => {
            #[unsafe(naked)]
            pub(super) unsafe extern "C" fn $name($($arg: $ty),*) -> isize {
                call_with_saved_gp!(
                    $application_gp,
                    ".option push",
                    ".option norelax",
                    "la gp, __global_pointer$",
                    ".option pop",
                    "call {target}";
                    target = sym $target
                )
            }
        };
    }

    kernel_entry!(open(_path: *const u8, _len: usize), linker::open, "mv a2, gp");
    kernel_entry!(
        symbol(_handle: usize, _name: *const u8, _len: usize, _result: *mut usize),
        linker::symbol,
        ""
    );
    kernel_entry!(close(_handle: usize), linker::close, "");
    kernel_entry!(finalize(), linker::finalize, "mv a0, gp");

    #[unsafe(naked)]
    unsafe extern "C" fn invoke(
        _address: usize,
        _app_gp: usize,
        _argc: usize,
        _argv: usize,
        _envp: usize,
    ) {
        call_with_saved_gp!(
            "mv t0, a0",
            "mv gp, a1",
            "mv a0, a2",
            "mv a1, a3",
            "mv a2, a4",
            "jalr t0";
        )
    }

    pub(in crate::loader) unsafe fn invoke_initializer(
        address: usize,
        app_gp: usize,
        [argc, argv, envp]: [usize; 3],
    ) {
        // SAFETY: the group retains the validated initializer and startup stack.
        unsafe { invoke(address, app_gp, argc, argv, envp) };
    }

    pub(in crate::loader) unsafe fn invoke_finalizer(address: usize, app_gp: usize) {
        // SAFETY: the group retains the validated finalizer through its return.
        unsafe { invoke(address, app_gp, 0, 0, 0) };
    }
}
