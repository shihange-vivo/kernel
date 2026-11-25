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

//! POSIX entry points for one native thread group's shared libraries.

use blueos_header::startup::{auxv, DynamicLinker};
use core::{
    cell::Cell,
    ffi::{c_char, c_int, c_ulong, c_void, CStr},
    mem::align_of,
    ptr,
};

pub const RTLD_LOCAL: c_int = 0;
pub const RTLD_LAZY: c_int = 1;
pub const RTLD_NOW: c_int = 2;
pub const RTLD_GLOBAL: c_int = 0x100;

#[thread_local]
static LAST_ERROR: Cell<Option<&'static CStr>> = Cell::new(None);

fn set_error(error: c_int) {
    LAST_ERROR.set(Some(match error {
        libc::ENOTSUP => c"dlopen: global visibility is not supported",
        libc::ENOSYS => c"dynamic loading is unavailable in this thread group",
        libc::EBUSY => c"the thread group is loading or finalizing a library",
        libc::EBADF => c"invalid dynamic library handle",
        libc::EINVAL => c"invalid dynamic loader argument",
        libc::ENOENT => c"dynamic symbol not found",
        libc::EIO => c"cannot read the library or its dependencies",
        libc::ENOEXEC => c"cannot link the library or its dependencies",
        libc::ENOMEM => c"insufficient memory or stack for dynamic loading",
        _ => c"dynamic loader operation failed",
    }));
}

fn runtime() -> Result<&'static DynamicLinker, c_int> {
    let address = crate::startup::getauxval(auxv::AT_BLUEKERNEL_DYNAMIC_LINKER as c_ulong) as usize;
    if address == 0 || !address.is_multiple_of(align_of::<DynamicLinker>()) {
        return Err(libc::ENOSYS);
    }
    // SAFETY: the trusted native launcher supplies immutable functions that
    // remain callable for the lifetime of this ELF thread group.
    Ok(unsafe { &*(address as *const DynamicLinker) })
}

fn result(status: isize) -> Result<usize, c_int> {
    if status < 0 {
        Err((-status) as c_int)
    } else {
        Ok(status as usize)
    }
}

fn open(path: Option<&CStr>, flags: c_int) -> Result<usize, c_int> {
    if flags & RTLD_GLOBAL != 0 {
        return Err(libc::ENOTSUP);
    }
    if !matches!(flags, RTLD_NOW | RTLD_LAZY) {
        return Err(libc::EINVAL);
    }
    if !crate::startup::linked_init_complete() {
        return Err(libc::ENOSYS);
    }
    let linker = runtime()?;
    let (address, len) = path.map_or((ptr::null(), 0), |path| {
        let bytes = path.to_bytes();
        (bytes.as_ptr(), bytes.len())
    });
    // SAFETY: nonempty paths supply the entire readable byte range for this call.
    result(unsafe { (linker.open)(address, len) })
}

/// Open a library and return an opaque group-wide handle. A null path opens
/// the main executable's startup scope. Both binding modes bind eagerly.
///
/// # Safety
/// A non-null path must point to a readable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void {
    let path = if path.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(path) })
    };
    match open(path, flags) {
        Ok(handle) => ptr::without_provenance_mut(handle),
        Err(error) => {
            set_error(error);
            ptr::null_mut()
        }
    }
}

/// Find a symbol in a handle's image and its dependencies.
///
/// # Safety
/// `name` must point to a readable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    if name.is_null() {
        set_error(libc::EINVAL);
        return ptr::null_mut();
    }
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    let mut address = 0usize;
    let loaded = runtime().and_then(|linker| {
        // SAFETY: the symbol bytes and writable result live through the call.
        result(unsafe {
            (linker.symbol)(handle.addr(), bytes.as_ptr(), bytes.len(), &raw mut address)
        })
    });
    match loaded {
        Ok(_) => ptr::with_exposed_provenance_mut(address),
        Err(error) => {
            set_error(error);
            ptr::null_mut()
        }
    }
}

/// Close a handle. The group retains published mappings until it exits.
#[unsafe(no_mangle)]
pub extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    // SAFETY: the handle is opaque and the native runtime validates it.
    match runtime().and_then(|linker| result(unsafe { (linker.close)(handle.addr()) })) {
        Ok(_) => 0,
        Err(error) => {
            set_error(error);
            -1
        }
    }
}

/// Return and clear the most recent loader error for the calling thread.
#[unsafe(no_mangle)]
pub extern "C" fn dlerror() -> *mut c_char {
    LAST_ERROR
        .take()
        .map_or(ptr::null_mut(), |error| error.as_ptr().cast_mut())
}

pub(crate) fn run_finalizers() -> Result<(), c_int> {
    let Ok(linker) = runtime() else {
        return Ok(());
    };
    // SAFETY: the application main thread has drained its group, so its only
    // remaining member can execute finalizers while the owner retains images.
    result(unsafe { (linker.finalize)() }).map(|_| ())
}
