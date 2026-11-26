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

//! Kernel host adapters for ELF loading and startup.
//!
//! The loader core stays independent of kernel types. This module supplies the
//! flat memory mapping, instruction publication and native profile, then hands
//! the owning `LoadedImage` back to the caller. Startup storage retains that
//! image and its ABI buffers. `crate::thread_group` manages member threads and
//! shared resources. The application libc runs startup callbacks, and the
//! group's dynamic linker runs callbacks for libraries opened at runtime.
//! Executing an image through a thread group requires `CONFIG_THREAD_GROUP=y`;
//! loading images and building their initial stacks remain available without it.

#[cfg(all(
    test,
    linux_glibc_smoke,
    any(thread_group, not(enable_vfs), not(enable_syscall))
))]
compile_error!("glibc smoke test requires Process, VFS, and syscall support");

pub mod adapters;
#[cfg(all(enable_dynamic_linker, thread_group, enable_vfs))]
mod linker;
#[cfg(all(linux_elf, not(thread_group), enable_vfs, enable_syscall))]
pub(crate) mod linux;
mod load;
#[cfg(all(enable_dynamic_linker, thread_group, enable_vfs))]
mod native_calls;
mod run;
mod startup;

pub use adapters::flat_memory::init_fixed_regions;
#[cfg(all(enable_dynamic_linker, thread_group, enable_vfs))]
pub(crate) use linker::{LinkerAccess, LinkerRuntime};
#[cfg(all(linux_elf, not(thread_group), enable_vfs, enable_syscall))]
pub use linux::{run_linux_from_path, LinuxRunError};
#[cfg(enable_dynamic_linker)]
pub use load::load_linked;
pub use load::{board_load_profile, load_image, load_request};
#[cfg(thread_group)]
pub use run::run;
#[cfg(all(enable_dynamic_linker, thread_group, enable_vfs))]
pub use run::run_linked_from_path;
#[cfg(all(enable_dynamic_linker, thread_group))]
pub use run::{prepare_linked, run_linked};
pub use run::{RunError, RunRequest};
pub use startup::{StartupArguments, StartupError, StartupStorage};
