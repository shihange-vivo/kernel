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

//! Kernel launch parameters and execution from a caller-provided ELF reader.
//!
//! The request and common errors are independent of the execution model. The
//! current `run` entry uses thread groups to retain application resources,
//! schedule the main thread and wait for every member's cleanup. It is compiled
//! with thread groups enabled. Process execution remains future work.
//! Callers supply a reader for memory, files or other storage, and can use
//! `load_image` and `StartupStorage` separately in either resource model.

use super::StartupError;
#[cfg(all(enable_dynamic_linker, thread_group))]
use super::{adapters::FlatImageAllocation, load_linked, startup::StartupFrame};
#[cfg(thread_group)]
use super::{load_image, StartupArguments, StartupStorage};
use crate::config;
#[cfg(all(enable_vfs, thread_group))]
use crate::thread_group::StandardIo;
#[cfg(all(enable_dynamic_linker, thread_group))]
use crate::thread_group::ThreadGroup;
#[cfg(thread_group)]
use crate::{
    thread::Stack,
    thread_group::{ThreadGroupError, ThreadGroupExit},
};
#[cfg(all(enable_dynamic_linker, thread_group))]
use alloc::vec::Vec;
#[cfg(thread_group)]
use blueos_loader::ElfReader;
use blueos_loader::LoadError;
#[cfg(all(enable_dynamic_linker, thread_group))]
use blueos_loader::{dynamic_linker::DependencyResolver, LoadedImages};
use core::ffi::CStr;

/// ELF ABI page granularity reported through AT_PAGESZ.
#[cfg(thread_group)]
const ABI_PAGE_SIZE: usize = 4096;

/// Startup parameters for one ELF launch, independent of its data source.
pub struct RunRequest<'a> {
    pub argv: &'a [&'a CStr],
    pub envp: &'a [&'a CStr],
    /// Optional program name copied into AT_EXECFN; not used to read the image.
    pub execfn: Option<&'a CStr>,
    /// Application main-thread stack size in bytes; defaults to
    /// [`config::DEFAULT_STACK_SIZE`].
    pub stack_size: usize,
    /// Borrow streams for descriptors 0/1/2. None opens the system console.
    #[cfg(all(enable_vfs, thread_group))]
    pub stdio: Option<&'a StandardIo>,
}

impl<'a> Default for RunRequest<'a> {
    fn default() -> Self {
        Self {
            argv: &[],
            envp: &[],
            execfn: None,
            stack_size: config::DEFAULT_STACK_SIZE,
            #[cfg(all(enable_vfs, thread_group))]
            stdio: None,
        }
    }
}

#[cfg(thread_group)]
impl RunRequest<'_> {
    fn arguments(&self) -> StartupArguments<'_> {
        StartupArguments {
            argv: self.argv,
            envp: self.envp,
            page_size: ABI_PAGE_SIZE,
            execfn: self.execfn,
            random: None,
        }
    }
}

impl<'a> core::fmt::Debug for RunRequest<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("RunRequest");
        debug
            .field("argv", &self.argv.len())
            .field("envp", &self.envp.len())
            .field("execfn", &self.execfn)
            .field("stack_size", &self.stack_size);
        #[cfg(all(enable_vfs, thread_group))]
        debug.field("redirected_stdio", &self.stdio.is_some());
        debug.finish()
    }
}

#[derive(Debug)]
pub enum RunError {
    Load(LoadError),
    Startup(StartupError),
    StackUnavailable,
    #[cfg(thread_group)]
    Start(ThreadGroupError),
}

impl From<LoadError> for RunError {
    fn from(error: LoadError) -> Self {
        Self::Load(error)
    }
}

impl From<StartupError> for RunError {
    fn from(error: StartupError) -> Self {
        Self::Startup(error)
    }
}

#[cfg(thread_group)]
impl From<ThreadGroupError> for RunError {
    fn from(error: ThreadGroupError) -> Self {
        Self::Start(error)
    }
}

/// Load an ELF from `reader` and run it to completion on this thread's
/// scheduler, returning its exit status. Blocks until every member thread of
/// the application has finished cleanup, then releases the image. Each CPU
/// completes instruction publication before running members or deferred cleanup.
///
/// Loading and startup preparation execute synchronously on the caller's stack;
/// the caller must provide sufficient stack for the loader and interrupt handling.
/// `request.stack_size` configures only the application's main thread.
///
/// # Safety
/// The image supplied by `reader` must be trusted native code using the standard ELF
/// initial-stack entry convention. Its users must remain thread group members;
/// see `StartupStorage::into_thread_group`.
#[cfg(thread_group)]
pub unsafe fn run(
    reader: impl ElfReader,
    request: &RunRequest<'_>,
) -> Result<ThreadGroupExit, RunError> {
    let image = load_image(reader)?;
    let stack = Stack::from_size(request.stack_size).ok_or(RunError::StackUnavailable)?;
    let storage = StartupStorage::new(image, stack, request.arguments())?;
    // SAFETY: the caller guarantees trusted native code; the group retains
    // the image and stack through all member cleanups.
    let mut thread_group = unsafe {
        storage.into_thread_group(
            #[cfg(enable_vfs)]
            request.stdio,
        )?
    };
    thread_group.start()?;
    thread_group.wait().map_err(Into::into)
}

/// Run a linked ELF and its dependencies as one native thread group.
/// The resolver opens the root and all dependencies on the caller's stack.
/// The group's main librs runtime executes the linked callback plans.
///
/// # Safety
/// All resolved images must be trusted native code. The root must use a librs
/// runtime that consumes the linked startup auxv entry and follows the thread
/// group exit contract of `run`. Users of any image must remain group members.
#[cfg(all(enable_dynamic_linker, thread_group))]
pub unsafe fn run_linked<D: DependencyResolver>(
    root: D::Key,
    resolver: &mut D,
    request: &RunRequest<'_>,
) -> Result<ThreadGroupExit, RunError>
where
    D::Key: Send + 'static,
{
    let images = load_linked(root, resolver)?;
    // SAFETY: the caller authorizes execution and follows the group exit contract.
    let mut group = unsafe { prepare_linked(images, request)? };
    group.start()?;
    group.wait().map_err(Into::into)
}

/// Prepare an unscheduled thread group from a finalized image graph.
///
/// The graph can include plugins preloaded before startup. The group takes
/// ownership of every mapping and the startup callback table through cleanup.
/// The root's librs runtime runs the complete initialization plan on startup
/// and the corresponding finalization plan on normal exit.
///
/// # Safety
/// All images must be trusted native code in the kernel's address space. The
/// root must use the librs linked startup and thread group exit conventions.
/// The mappings must have been published for every CPU that can execute them.
/// The group must be the first to execute these images, and their code and data
/// must remain in use only by group members during its lifetime.
#[cfg(all(enable_dynamic_linker, thread_group))]
pub unsafe fn prepare_linked<K: Eq + Send + 'static>(
    images: LoadedImages<K, FlatImageAllocation>,
    request: &RunRequest<'_>,
) -> Result<ThreadGroup, RunError> {
    if images.pending_plugin_init().is_some() {
        return Err(StartupError::LifecycleUnavailable.into());
    }
    let init_count = images
        .preinit()
        .len()
        .checked_add(images.init().count())
        .ok_or(StartupError::LifecycleUnavailable)?;
    let fini_count = images.fini().count();
    let words = init_count
        .checked_add(fini_count)
        .and_then(|count| count.checked_add(2))
        .ok_or(StartupError::LifecycleUnavailable)?;
    let mut lifecycle = Vec::new();
    lifecycle
        .try_reserve_exact(words)
        .map_err(|_| StartupError::LifecycleUnavailable)?;
    lifecycle.extend([init_count, fini_count]);
    for address in images
        .preinit()
        .iter()
        .copied()
        .chain(images.init())
        .chain(images.fini())
    {
        lifecycle.push(usize::try_from(address.get()).map_err(|_| StartupError::InvalidAddress)?);
    }

    let stack = Stack::from_size(request.stack_size).ok_or(RunError::StackUnavailable)?;
    let frame = StartupFrame::new(images.root(), stack, request.arguments(), Some(&lifecycle))?;
    // SAFETY: the owner keeps every mapping and the immutable auxv payload
    // alive through cleanup. The caller authorizes the native entry.
    unsafe {
        frame.into_thread_group(
            (images, lifecycle),
            #[cfg(enable_vfs)]
            request.stdio,
        )
    }
    .map_err(Into::into)
}
