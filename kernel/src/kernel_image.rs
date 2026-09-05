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

//! Bootable kernel image without static applications (C29, §18.2).
//!
//! The boot seed path assembles the application stack and launches the
//! dynamic bootstrap shell before the scheduler starts, so this image only
//! carries the kernel and the rsrt runtime. `main` is a stub: the scheduler
//! takes over in `boot::init` and this thread is never resumed.

#![no_main]
#![no_std]

extern crate alloc;
extern crate rsrt;

/// Anchor the kernel crate into the link. A boot image without static
/// applications has no application code whose kernel references would pull
/// the kernel objects, and the reset vector table lives inside the kernel's
/// arch module — so without this anchor the linker would garbage-collect the
/// whole kernel out of the image.
#[used]
static KERNEL_ANCHOR: extern "C" fn(&'static blueos::arch::Context) -> usize =
    blueos::arch::bk_debug_syscall;

#[no_mangle]
pub extern "C" fn main() {
    // The dynamic bootstrap shell owns the console from here on.
}
