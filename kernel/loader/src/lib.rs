// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
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
#![no_main]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, test_runner(loader_test_runner))]
#![cfg_attr(test, reexport_test_harness_main = "loader_test_main")]
#![feature(c_size_t)]
#![cfg_attr(compatible_old_toolchain, feature(unsigned_is_multiple_of))]

//! ELF loading and dynamic linking with host-supplied platform capabilities.
//!
//! Call [`load`] with a [`LoadRequest`], independent [`LoadServices`] and a
//! [`LoadPublisher`]. Use [`prepare_load`] to inspect the complete immutable
//! manifest before publication. Dropping preparation rolls back allocations
//! and reservation permits; the returned owner retains the published resources.
//! Select [`LoadRequest::executable`] for a fresh launch or
//! [`LoadRequest::shared_object`] for a runtime library load. Ready images
//! reuse published dependency snapshots without reopening their ELF files.
//!
//! Core loading entry points and [`LoadError`]/[`LoadResult`] are available
//! at the crate root. Reader and memory contracts live in
//! [`reader`] and [`memory`]; ABI profiles and resource
//! limits live in [`profile`]. The [`error`] module provides error details.
//!
//! # Implementation map
//!
//! Start with `loading/load.rs` for the complete load flow. `loading/` owns
//! host interaction and result assembly; `image/` loads one ELF image;
//! `dynamic_linker/` links the image closure. `memory/` supplies allocation,
//! rollback and cache contracts; `elf/` decodes file structures and
//! `relocation/` implements architecture-specific relocation rules.

extern crate alloc;

// Public API organized by responsibility.
pub mod error;
pub mod memory;
pub mod profile;
pub mod reader;
pub mod trace;

// Loading and linking implementation details.
mod dynamic_linker;
mod elf;
mod identity;
mod image;
mod loading;
pub use identity::{ArtifactId, ExecutionDomainId, ImageInstanceId, ImageKey};
mod relocation;

// Frequently used entry points and types.
pub use error::{LoadError, LoadResult};
pub use loading::{
    load, prepare_load, ArtifactInfo, ArtifactResolver, ImageCandidate, ImageDependency,
    ImageHandle, ImagePin, ImageRepository, LifecycleEntry, LoadPublisher, LoadRequest,
    LoadReservation, LoadResources, LoadServices, LoadedImage, LocalPin, LocalRepository,
    LocalReservation, NamespaceSnapshot, OpenedArtifact, PreparedLoad, PublicationManifest,
    ReservedImage, RetainResources,
};

#[cfg(test)]
use blueos_infra::no_let_underscore::IgnoreResult;

#[cfg(test)]
extern crate rsrt;

#[cfg(test)]
use alloc::sync::Arc;
#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub fn loader_test_runner(tests: &[&dyn Fn()]) {
    semihosting::println!("Loader unittest started");
    semihosting::println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    semihosting::println!("Loader unittest ended");

    #[cfg(coverage)]
    blueos::coverage::write_coverage_data();
}

#[cfg(test)]
fn run_loader_tests_on_own_stack() {
    // Debug builds can overflow the 12 KiB main-thread stack in loader decode paths.
    const STACK_SIZE: usize = 64 * 1024;

    let done = Arc::new(AtomicUsize::new(0));
    let worker_done = done.clone();
    let worker = blueos::thread::spawn_with_stack(STACK_SIZE, move || {
        librs::pthread::register_my_posix_tcb();
        loader_test_main();
        worker_done.store(1, Ordering::Release);
        blueos::sync::atomic_wake(&worker_done, usize::MAX).ignore_result();
    });
    assert!(
        worker.is_some(),
        "loader unittest: no {STACK_SIZE}-byte stack"
    );

    while done.load(Ordering::Acquire) == 0 {
        blueos::sync::atomic_wait(&done, 0, blueos::time::Tick::MAX).ignore_result();
    }
}

#[cfg(test)]
#[no_mangle]
extern "C" fn main() -> i32 {
    librs::pthread::register_my_posix_tcb();
    run_loader_tests_on_own_stack();
    0
}
