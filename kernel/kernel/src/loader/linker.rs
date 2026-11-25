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

//! Dynamic linking and loaded images for one native thread group.

use super::adapters::{FlatImageAllocation, KernelCodeCache, MemoryMapper, VfsElfReader};
use crate::{arch, scheduler, thread_group, vfs};
use alloc::{string::String, vec::Vec};
use blueos_loader::{
    dynamic_linker::DependencyResolver,
    error::{ErrorContext, LoadErrorKind},
    memory::TargetAddress,
    LoadAndLinkRequest, LoadError, LoadResult, LoadedImages, PluginLoad,
};
use core::{
    ffi::c_int,
    slice, str,
    sync::atomic::{AtomicUsize, Ordering},
};

// First-time loading uses the opening thread's stack. These thresholds leave
// headroom above the loader's observed stack use on the QEMU targets.
// Constructors also run on this stack and have their own stack requirements.
const OPEN_STACK_RESERVE: usize = if cfg!(debug_assertions) { 7 } else { 6 } * 1024;

// Handles are opaque and never recycled. A handle from another group cannot
// match a local open, even if the two groups loaded the same path.
static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(1);

pub(super) struct VfsResolver;

impl VfsResolver {
    pub(super) fn path(path: &str) -> LoadResult<String> {
        if path.is_empty() {
            return Err(source_error());
        }
        if path.starts_with('/') {
            return vfs::normalize_path(path).ok_or_else(source_error);
        }
        vfs::join_path(&vfs::get_working_dir().get_full_path(), path).ok_or_else(source_error)
    }

    fn resolve_path(requester: &str, name: &str) -> LoadResult<String> {
        if name.is_empty() {
            return Err(source_error());
        }
        let (directory, _) = requester.rsplit_once('/').ok_or_else(source_error)?;
        vfs::join_path(if directory.is_empty() { "/" } else { directory }, name)
            .ok_or_else(source_error)
    }
}

impl DependencyResolver for VfsResolver {
    type Key = String;
    type Reader = VfsElfReader;

    fn resolve(&mut self, requester: &String, name: &[u8]) -> LoadResult<String> {
        Self::resolve_path(requester, str::from_utf8(name).map_err(|_| source_error())?)
    }

    fn open(&mut self, key: &String) -> LoadResult<Self::Reader> {
        VfsElfReader::new(vfs::open_path(key, libc::O_RDONLY, 0).map_err(|_| source_error())?)
    }
}

// Only the current group member uses these native addresses. Taking a copy
// lets the runtime release all group locks and references before calling ELF.
#[derive(Clone, Copy)]
struct CallbackList {
    address: *const usize,
    count: usize,
}

impl CallbackList {
    fn from_slice(entries: &[usize]) -> Self {
        Self {
            address: entries.as_ptr(),
            count: entries.len(),
        }
    }

    /// # Safety
    /// The group still owns this immutable list for the duration of the read.
    unsafe fn addresses(&self) -> &[usize] {
        unsafe { slice::from_raw_parts(self.address, self.count) }
    }
}

enum Opened {
    Published(usize),
    Pending(CallbackList, [usize; 3]),
}

pub(crate) enum LinkerAccess {
    Open,
    Existing,
    Finalize,
}

struct Handle {
    id: usize,
    image: usize,
}

#[must_use = "retain the callbacks and unconfirmed handle until initialization completes"]
struct Pending {
    thread: usize,
    handle: usize,
    initializers: Vec<usize>,
    fini_start: usize,
}

/// Owns the startup images and the libraries loaded by the group at runtime.
#[must_use = "retain the linker runtime to keep the group's mappings alive"]
pub(crate) struct LinkerRuntime {
    images: LoadedImages<String, FlatImageAllocation>,
    request: LoadAndLinkRequest,
    // Native argc, argv and envp. The group retains the original stack.
    arguments: [usize; 3],
    handles: Vec<Handle>,
    pending: Option<Pending>,
    // Stored in reverse call order, so opening a new library only appends entries.
    finalizers: Vec<usize>,
}

impl LinkerRuntime {
    pub(super) fn new(
        images: LoadedImages<String, FlatImageAllocation>,
        request: LoadAndLinkRequest,
        arguments: [usize; 3],
    ) -> Self {
        Self {
            images,
            request,
            arguments,
            handles: Vec::new(),
            pending: None,
            finalizers: Vec::new(),
        }
    }

    fn handle_index(&self, handle: usize) -> Result<usize, c_int> {
        self.handles
            .iter()
            .position(|entry| entry.id == handle)
            .ok_or(libc::EBADF)
    }

    #[inline(never)]
    fn prepare_open(&mut self, thread: usize, path: Option<&[u8]>) -> Result<Opened, c_int> {
        self.handles.try_reserve(1).map_err(|_| libc::ENOMEM)?;
        let id = NEXT_HANDLE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                (id < isize::MAX as usize).then_some(id + 1)
            })
            .map_err(|_| libc::EMFILE)?;
        let Some(path) = path else {
            self.handles.push(Handle { id, image: 0 });
            return Ok(Opened::Published(id));
        };

        let path = str::from_utf8(path).map_err(|_| libc::EINVAL)?;
        let key = if path.contains('/') {
            VfsResolver::path(path)
        } else {
            VfsResolver::resolve_path(self.images.images()[0].key(), path)
        }
        .map_err(load_errno)?;
        if arch::current_sp().saturating_sub(scheduler::current_thread_ref().stack_base())
            < OPEN_STACK_RESERVE
            && self.images.images().iter().all(|image| image.key() != &key)
        {
            return Err(libc::ENOMEM);
        }
        let result = self
            .images
            .begin_plugin_load(
                key,
                self.request,
                &mut VfsResolver,
                &mut MemoryMapper::new(),
                &mut KernelCodeCache::new(),
            )
            .map_err(load_errno)?;
        if let PluginLoad::Existing(image) = result {
            self.handles.push(Handle { id, image });
            return Ok(Opened::Published(id));
        }

        let fini_start = self.finalizers.len();
        let mut initializers = Vec::new();
        let result = append_callbacks(
            &mut initializers,
            self.images
                .pending_plugin_init()
                .expect("pending image batch"),
        )
        .and_then(|()| {
            append_callbacks(
                &mut self.finalizers,
                self.images
                    .pending_plugin_fini()
                    .expect("pending image batch")
                    .rev(),
            )
        });
        if let Err(error) = result {
            self.finalizers.truncate(fini_start);
            self.images.cancel_plugin_load();
            return Err(error);
        }
        let callbacks = CallbackList::from_slice(&initializers);
        self.pending = Some(Pending {
            thread,
            handle: id,
            initializers,
            fini_start,
        });
        Ok(Opened::Pending(callbacks, self.arguments))
    }

    fn publish(&mut self, thread: usize) -> Result<usize, c_int> {
        if !self.pending.as_ref().is_some_and(|p| p.thread == thread) {
            return Err(libc::EPERM);
        }
        let image = self.images.finish_plugin_load().ok_or(libc::EINVAL)?;
        let pending = self.pending.take().expect("validated pending plugin");
        let id = pending.handle;
        drop(pending.initializers);
        self.handles.push(Handle { id, image });
        Ok(id)
    }

    fn symbol(&self, handle: usize, name: &[u8]) -> Result<usize, c_int> {
        let image = self.handles[self.handle_index(handle)?].image;
        let address = self
            .images
            .lookup_symbol(image, name)
            .map_err(load_errno)?
            .ok_or(libc::ENOENT)?;
        usize::try_from(address.get()).map_err(|_| libc::EOVERFLOW)
    }

    fn close(&mut self, handle: usize) -> Result<usize, c_int> {
        let index = self.handle_index(handle)?;
        self.handles.swap_remove(index);
        Ok(0)
    }

    fn finalizers(&self) -> CallbackList {
        let count = self
            .pending
            .as_ref()
            .map_or(self.finalizers.len(), |p| p.fini_start);
        CallbackList::from_slice(&self.finalizers[..count])
    }
}

fn append_callbacks(
    list: &mut Vec<usize>,
    callbacks: impl Iterator<Item = TargetAddress>,
) -> Result<(), c_int> {
    for address in callbacks {
        list.try_reserve(1).map_err(|_| libc::ENOMEM)?;
        list.push(usize::try_from(address.get()).map_err(|_| libc::EOVERFLOW)?);
    }
    Ok(())
}

fn source_error() -> LoadError {
    LoadError::new(LoadErrorKind::Io, ErrorContext::None)
}

fn load_errno(error: LoadError) -> c_int {
    match error.kind() {
        LoadErrorKind::OutOfMemory => libc::ENOMEM,
        LoadErrorKind::Io => libc::EIO,
        LoadErrorKind::PluginLoadPending => libc::EBUSY,
        _ => libc::ENOEXEC,
    }
}

fn with_linker<T>(
    access: LinkerAccess,
    operation: impl FnOnce(&mut LinkerRuntime, usize) -> Result<T, c_int>,
) -> Result<T, c_int> {
    let thread = scheduler::current_thread_id();
    let group = thread_group::for_thread(thread).ok_or(libc::ENOSYS)?;
    group.with_linker(thread, access, |linker| operation(linker, thread))
}

fn native_result(result: Result<usize, c_int>) -> isize {
    result.map_or_else(|error| -(error as isize), |value| value as isize)
}

/// # Safety
/// The native caller supplies path bytes that remain readable for this call.
/// A zero address and length open the main program's startup symbol scope.
pub(super) unsafe extern "C" fn open(path: *const u8, len: usize, app_gp: usize) -> isize {
    native_result((|| {
        let path = if path.is_null() && len == 0 {
            None
        } else {
            // SAFETY: the native caller supplies the path bytes.
            Some(unsafe { input(path, len) }?)
        };
        let opened = with_linker(LinkerAccess::Open, |linker, thread| {
            if linker.pending.is_some() {
                return Err(libc::EBUSY);
            }
            linker.prepare_open(thread, path)
        })?;

        match opened {
            Opened::Published(handle) => Ok(handle),
            Opened::Pending(callbacks, arguments) => {
                // The group owns the pending mappings and callback addresses.
                // No lock or Arc may live on this call frame, since a
                // constructor can retire the caller without unwinding.
                for &address in unsafe { callbacks.addresses() } {
                    unsafe { super::native_calls::invoke_initializer(address, app_gp, arguments) };
                }
                with_linker(LinkerAccess::Existing, LinkerRuntime::publish)
            }
        }
    })())
}

/// # Safety
/// The caller supplies readable name bytes and a writable native word.
pub(super) unsafe extern "C" fn symbol(
    handle: usize,
    name: *const u8,
    len: usize,
    result: *mut usize,
) -> isize {
    native_result((|| {
        if result.is_null() || !result.is_aligned() {
            return Err(libc::EINVAL);
        }
        // SAFETY: the caller supplies len readable bytes at name.
        let name = unsafe { input(name, len) }?;
        let address = with_linker(LinkerAccess::Existing, |linker, _| {
            linker.symbol(handle, name)
        })?;
        // SAFETY: the caller supplies aligned writable output storage.
        unsafe { result.write(address) };
        Ok(0)
    })())
}

pub(super) extern "C" fn close(handle: usize) -> isize {
    native_result(with_linker(LinkerAccess::Existing, |linker, _| {
        linker.close(handle)
    }))
}

pub(super) extern "C" fn finalize(app_gp: usize) -> isize {
    native_result((|| {
        let callbacks = with_linker(LinkerAccess::Finalize, |linker, _| Ok(linker.finalizers()))?;
        // No member other than the exiting main thread can use the group now.
        for &address in unsafe { callbacks.addresses() }.iter().rev() {
            unsafe { super::native_calls::invoke_finalizer(address, app_gp) };
        }
        Ok(0)
    })())
}

unsafe fn input<'a>(address: *const u8, len: usize) -> Result<&'a [u8], c_int> {
    if address.is_null() || len == 0 || len > 4096 {
        return Err(libc::EINVAL);
    }
    // SAFETY: the native interface requires the input to remain readable.
    Ok(unsafe { slice::from_raw_parts(address, len) })
}
