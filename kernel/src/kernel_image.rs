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

//! Dedicated bootable kernel image for the dynamic shell (C29, §18.2).
//!
//! Boot installs the embedded system image and initializes the application
//! runtime before the scheduler starts. This image's static entry then launches
//! the dynamic bootstrap shell, keeping that interactive application out of
//! unrelated test images.

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
static KERNEL_ANCHOR: extern "C" fn() -> usize = blueos::arch::current_sp;

#[no_mangle]
pub extern "C" fn main() {
    blueos::application::runtime::launch_bootstrap_shell();
}
