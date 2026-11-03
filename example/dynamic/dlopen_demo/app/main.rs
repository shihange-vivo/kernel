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

#![no_std]
#![no_main]
#![feature(c_variadic)]

use core::{
    ffi::{c_char, c_int, c_void, CStr},
    sync::atomic::{AtomicUsize, Ordering},
};
const NOW: i32 = 2;
const GLOBAL: i32 = 0x100;
const DEFAULT: *mut c_void = core::ptr::null_mut();

extern "C" {
    fn dlopen(name: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *mut c_char;
    fn write(fd: c_int, data: *const u8, len: usize) -> isize;
    fn pthread_create(
        tid: *mut usize,
        attr: *const c_void,
        entry: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_join(tid: usize, result: *mut *mut c_void) -> c_int;
    fn usleep(microseconds: u32) -> c_int;
    fn dl_base_count() -> usize;
    fn dlopen_c_api_probe() -> c_int;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn read(fd: c_int, data: *mut u8, len: usize) -> isize;
    fn close(fd: c_int) -> c_int;
}

static EVENTS: [AtomicUsize; 7] = [const { AtomicUsize::new(0) }; 7];
static WORKERS_OPEN: AtomicUsize = AtomicUsize::new(0);
static SHARED_HANDLE: AtomicUsize = AtomicUsize::new(0);
static EXIT_MODE: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
pub extern "C" fn dl_event(tag: usize) {
    if tag == 2 || tag == 3 {
        assert!(
            EVENTS[0].load(Ordering::SeqCst) > EVENTS[1].load(Ordering::SeqCst),
            "dependency must outlive its consumer",
        );
    }
    EVENTS[tag].fetch_add(1, Ordering::SeqCst);
    if tag == 3 && EXIT_MODE.load(Ordering::SeqCst) != 0 {
        assert_eq!(EVENTS[6].load(Ordering::SeqCst), 1);
        print(b"DLOPEN_EXIT_FINI\n");
    }
    if tag == 6 {
        assert_eq!(EVENTS[3].load(Ordering::SeqCst), 0);
        print(b"DLOPEN_KEY_FINI\n");
    }
    if tag == 5 && EXIT_MODE.load(Ordering::SeqCst) != 0 {
        print(b"DLOPEN_EXIT_NESTED_FINI\n");
    }
}

fn print(message: &[u8]) {
    // SAFETY: the slice supplies exactly len readable bytes for this
    // synchronous call; the application pins its libc provider throughout.
    unsafe {
        write(1, message.as_ptr(), message.len());
    }
}

fn open_object(name: Option<&[u8]>, flags: i32) -> *mut c_void {
    let name = name.map(|bytes| CStr::from_bytes_with_nul(bytes).expect("fixture C filename"));
    let pointer = name.map_or(core::ptr::null(), CStr::as_ptr);
    // SAFETY: pointer is either NULL (the supported main-image query) or a
    // borrowed terminated string that outlives the call. Flags are validated
    // by libc/kernel; the returned handle is an opaque token, not a pointer.
    unsafe { dlopen(pointer, flags) }
}

fn lookup_symbol(handle: *mut c_void, name: Option<&[u8]>) -> *mut c_void {
    let name = name.map(|bytes| CStr::from_bytes_with_nul(bytes).expect("fixture C symbol"));
    let pointer = name.map_or(core::ptr::null(), CStr::as_ptr);
    // SAFETY: the optional symbol string is borrowed and terminated; NULL
    // deliberately tests libc's error path. Kernel validation treats every
    // handle, including invalid test values, as an opaque numeric token.
    unsafe { dlsym(handle, pointer) }
}

fn close_object(handle: *mut c_void) -> c_int {
    // SAFETY: dlclose accepts an opaque token and validates ownership before
    // accessing objects; it never dereferences the token as caller memory.
    unsafe { dlclose(handle) }
}

fn error_pointer() -> *mut c_char {
    // SAFETY: dlerror has no pointer inputs. It returns this thread's own
    // error buffer; callers only inspect NULL or borrow it until the next call.
    unsafe { dlerror() }
}

fn pause(microseconds: u32) {
    // SAFETY: usleep takes only a scalar delay and uses the pinned libc export.
    unsafe { usleep(microseconds) };
}

fn load(name: &[u8], flags: i32) -> *mut c_void {
    let handle = open_object(Some(name), flags);
    if handle.is_null() {
        let error = error_pointer();
        if !error.is_null() {
            // SAFETY: dlerror returns a terminated thread-local buffer; no
            // later dlerror or loader call mutates it while print reads it.
            let error = unsafe { CStr::from_ptr(error) };
            print(error.to_bytes());
            print(b"\n");
        }
        panic!("dlopen fixture failed");
    }
    handle
}

/// Resolve and synchronously call a usize-valued fixture export.
///
/// # Safety
/// name must identify an extern C fn() -> usize export. Its calling
/// preconditions, including any fixture serialization, must hold. The caller
/// must keep the selected provider loaded through the entire invocation.
// SAFETY: the caller establishes the exact signature and provider lifetime;
// lookup checks the name and this helper rejects NULL before conversion.
unsafe fn value(handle: *mut c_void, name: &[u8]) -> usize {
    let pointer = lookup_symbol(handle, Some(name));
    assert!(!pointer.is_null());
    // SAFETY: callers select only the fixture's extern C fn() -> usize
    // exports and retain their open handle or GLOBAL provider through this
    // call.
    let function: extern "C" fn() -> usize = unsafe { core::mem::transmute(pointer) };
    function()
}

/// Resolve and synchronously call an i32-valued fixture export.
///
/// # Safety
/// name must identify an extern C fn() -> i32 export. The caller must meet
/// that export's calling preconditions and keep its provider loaded until the
/// synchronous invocation returns, including during any recursive callbacks.
// SAFETY: the caller establishes the i32 C signature and pins the provider;
// this helper validates lookup success before constructing the function value.
unsafe fn value_i32(handle: *mut c_void, name: &[u8]) -> i32 {
    let pointer = lookup_symbol(handle, Some(name));
    assert!(!pointer.is_null());
    // SAFETY: the caller selects the known i32 C signature and retains code.
    let function: extern "C" fn() -> i32 = unsafe { core::mem::transmute(pointer) };
    function()
}

/// Resolve and synchronously call a u32-valued fixture export.
///
/// # Safety
/// name must identify an extern C fn() -> u32 export. The caller must meet
/// that export's calling preconditions and keep its provider loaded until the
/// synchronous invocation returns, including during any recursive callbacks.
// SAFETY: the caller establishes the u32 C signature and pins the provider;
// this helper validates lookup success before constructing the function value.
unsafe fn value_u32(handle: *mut c_void, name: &[u8]) -> u32 {
    let pointer = lookup_symbol(handle, Some(name));
    assert!(!pointer.is_null());
    // SAFETY: the caller selects the known u32 C signature and retains code.
    let function: extern "C" fn() -> u32 = unsafe { core::mem::transmute(pointer) };
    function()
}

fn error_once() {
    assert!(!error_pointer().is_null());
    assert!(error_pointer().is_null());
}

fn failures_and_startup() {
    assert!(error_pointer().is_null());
    // SAFETY: this declared C export takes no pointer arguments and its
    // startup dependency remains retained throughout the application.
    assert_eq!(unsafe { dlopen_c_api_probe() }, 0);
    assert!(open_object(Some(b"missing.so\0"), NOW).is_null());
    error_once();
    for flags in [0, 3, 0x4000] {
        assert!(open_object(None, flags).is_null());
        error_once();
    }
    assert_eq!(close_object(DEFAULT), -1);
    error_once();
    assert_eq!(close_object(usize::MAX as *mut c_void), -1);
    error_once();
    assert!(lookup_symbol(DEFAULT, None).is_null());
    error_once();
    let root = open_object(None, NOW);
    assert!(!root.is_null());
    assert!(!lookup_symbol(root, Some(b"main\0")).is_null());
    assert!(!lookup_symbol(root, Some(b"write\0")).is_null());
    assert_eq!(close_object(root), 0);
    // SAFETY: this declared C export takes no pointer arguments and its
    // startup dependency remains retained throughout the application.
    assert_eq!(unsafe { dl_base_count() }, 1);
    let base = load(b"libdl_base.so.1\0", NOW);
    // SAFETY: dl_base_count is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(base, b"dl_base_count\0") }, 1);
    assert_eq!(close_object(base), 0);
    // SAFETY: this declared C export takes no pointer arguments and its
    // startup dependency remains retained throughout the application.
    assert_eq!(unsafe { dl_base_count() }, 1);
    for _ in 0..3 {
        assert!(open_object(Some(b"libdl_bad.so.1\0"), NOW).is_null());
        error_once();
    }
    let system = load(b"libscope_sys.so\0", NOW);
    // SAFETY: sys_report is the known C fn() -> i32 export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value_i32(system, b"sys_report\0") }, 777);
    // SAFETY: sys_ctor_count is the known C fn() -> u32 export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value_u32(system, b"sys_ctor_count\0") }, 1);
    let same = load(b"/system/lib/libscope_sys.so.1\0", NOW);
    assert_eq!(same, system);
    assert_eq!(close_object(system), 0);
    // SAFETY: sys_ctor_count is the known C fn() -> u32 export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value_u32(same, b"sys_ctor_count\0") }, 1);
    assert_eq!(close_object(same), 0);
    let fresh = load(b"libscope_sys.so\0", NOW);
    assert_ne!(fresh, system);
    // SAFETY: sys_ctor_count is the known C fn() -> u32 export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value_u32(fresh, b"sys_ctor_count\0") }, 1);
    assert_eq!(close_object(fresh), 0);

    print(b"DLOPEN_FAILURES_OK\n");
}

fn reference_counts() {
    let dep_fini = EVENTS[1].load(Ordering::SeqCst);
    let plugin_fini = EVENTS[3].load(Ordering::SeqCst);
    let first = load(b"libdl_plugin.so.1\0", NOW);
    // SAFETY: dl_plugin_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(first, b"dl_plugin_value\0") }, 42);
    // SAFETY: dl_dep_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(first, b"dl_dep_value\0") }, 41);
    // SAFETY: dl_plugin_ctor_count is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(first, b"dl_plugin_ctor_count\0") }, 1);
    // SAFETY: dl_plugin_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(first, b"dl_plugin_next\0") }, 1);
    assert!(error_pointer().is_null());
    assert!(lookup_symbol(first, Some(b"dl_absolute_zero\0")).is_null());
    assert!(
        error_pointer().is_null(),
        "a defined zero-valued symbol is not an error",
    );
    assert!(lookup_symbol(first, Some(b"dl_plugin_hidden\0")).is_null());
    error_once();
    assert!(lookup_symbol(DEFAULT, Some(b"dl_plugin_value\0")).is_null());
    error_once();
    let again = load(b"/apps/dlopen/lib/../lib/libdl_plugin.so.1\0", NOW);
    assert_eq!(first, again);
    // SAFETY: dl_plugin_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(again, b"dl_plugin_next\0") }, 2);
    assert_eq!(close_object(first), 0);
    // SAFETY: dl_plugin_ctor_count is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(again, b"dl_plugin_ctor_count\0") }, 1);
    assert_eq!(EVENTS[3].load(Ordering::SeqCst), plugin_fini);
    assert_eq!(close_object(again), 0);
    assert_eq!(EVENTS[3].load(Ordering::SeqCst), plugin_fini + 1);
    assert_eq!(EVENTS[1].load(Ordering::SeqCst), dep_fini + 1);

    // GLOBAL includes a dependency that was already loaded LOCAL.
    let dep = load(b"libdl_dep.so.1\0", NOW);
    let plugin = load(b"libdl_plugin.so.1\0", NOW | GLOBAL);
    // SAFETY: dl_dep_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(DEFAULT, b"dl_dep_value\0") }, 41);
    assert_eq!(close_object(dep), 0);
    assert_eq!(close_object(plugin), 0);
    assert!(lookup_symbol(DEFAULT, Some(b"dl_dep_value\0")).is_null());
    error_once();
    assert!(lookup_symbol(first, Some(b"dl_plugin_value\0")).is_null());
    error_once();
    assert_eq!(close_object(first), -1);
    error_once();
    let fresh = load(b"libdl_plugin.so.1\0", NOW);
    assert_ne!(fresh, first);
    // SAFETY: dl_plugin_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(fresh, b"dl_plugin_next\0") }, 1);
    // SAFETY: dl_plugin_ctor_count is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(fresh, b"dl_plugin_ctor_count\0") }, 1);
    assert_eq!(close_object(fresh), 0);

    let dep = load(b"libdl_dep.so.1\0", NOW);
    let dep_fini = EVENTS[1].load(Ordering::SeqCst);
    let plugin = load(b"libdl_plugin.so.1\0", NOW);
    assert_eq!(close_object(dep), 0);
    assert_eq!(EVENTS[1].load(Ordering::SeqCst), dep_fini);
    // SAFETY: dl_plugin_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(plugin, b"dl_plugin_value\0") }, 42);
    assert_eq!(close_object(plugin), 0);
    assert_eq!(EVENTS[1].load(Ordering::SeqCst), dep_fini + 1);

    print(b"DLOPEN_REFS_OK\n");
}

fn global_scope() {
    let provider = load(b"libdl_provider.so.1\0", NOW);
    assert!(lookup_symbol(DEFAULT, Some(b"dl_runtime_provider\0")).is_null());
    error_once();
    // LAZY is admitted but unresolved strong references still fail eagerly.
    assert!(open_object(Some(b"libdl_consumer.so.1\0"), 1).is_null());
    error_once();
    let promoted = load(b"libdl_provider.so.1\0", NOW | GLOBAL);
    assert_eq!(provider, promoted);
    // SAFETY: dl_runtime_provider is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(DEFAULT, b"dl_runtime_provider\0") }, 70);
    let root = open_object(None, NOW);
    // SAFETY: dl_runtime_provider is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(root, b"dl_runtime_provider\0") }, 70);
    let consumer = load(b"libdl_consumer.so.1\0", NOW);
    // SAFETY: dl_consumer_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(consumer, b"dl_consumer_value\0") }, 77);
    assert_eq!(close_object(provider), 0);
    assert_eq!(close_object(promoted), 0);
    // The consumer's relocation keeps the now-unopened provider mapped.
    // SAFETY: dl_consumer_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(consumer, b"dl_consumer_value\0") }, 77);
    assert_eq!(close_object(consumer), 0);
    assert!(lookup_symbol(root, Some(b"dl_runtime_provider\0")).is_null());
    error_once();
    assert_eq!(close_object(root), 0);

    print(b"DLOPEN_GLOBAL_OK\n");
}

fn recursive_and_tls() {
    let nested = load(b"libdl_nested.so.1\0", NOW);
    // SAFETY: dl_nested_value is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(nested, b"dl_nested_value\0") }, 41);
    assert_eq!(EVENTS[4].load(Ordering::SeqCst), 1);
    assert_eq!(close_object(nested), 0);
    assert_eq!(EVENTS[5].load(Ordering::SeqCst), 1);
    let tls = load(b"libdl_tls.so.1\0", NOW);
    // SAFETY: dl_tls_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(tls, b"dl_tls_next\0") }, 8);
    // SAFETY: dl_tls_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(tls, b"dl_tls_next\0") }, 9);
    assert_eq!(close_object(tls), 0);
    let fresh = load(b"libdl_tls.so.1\0", NOW);
    assert_ne!(tls, fresh);
    // SAFETY: dl_tls_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(fresh, b"dl_tls_next\0") }, 8);
    assert_eq!(close_object(fresh), 0);

    print(b"DLOPEN_RECURSIVE_TLS_OK\n");
}

extern "C" fn concurrent_worker(_: *mut c_void) -> *mut c_void {
    assert!(error_pointer().is_null(), "dlerror must be thread-local");
    let handle = load(b"libdl_tls.so.1\0", NOW);
    let previous = SHARED_HANDLE
        .compare_exchange(0, handle as usize, Ordering::SeqCst, Ordering::SeqCst)
        .unwrap_or_else(|old| old);
    assert!(previous == 0 || previous == handle as usize);
    WORKERS_OPEN.fetch_add(1, Ordering::SeqCst);
    while WORKERS_OPEN.load(Ordering::SeqCst) != 4 {
        pause(10_000);
    }
    // SAFETY: dl_tls_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(handle, b"dl_tls_next\0") }, 8);
    // SAFETY: dl_tls_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(handle, b"dl_tls_next\0") }, 9);
    assert!(lookup_symbol(handle, Some(b"missing_worker_symbol\0")).is_null());
    error_once();
    assert_eq!(close_object(handle), 0);
    core::ptr::null_mut()
}

fn concurrent_and_errors() {
    assert!(lookup_symbol(DEFAULT, Some(b"missing_main_symbol\0")).is_null());
    let mut threads = [0usize; 4];
    for thread in &mut threads {
        assert_eq!(
            // SAFETY: thread is a writable local id slot and NULL attr selects
            // defaults. concurrent_worker has the C entry signature and ignores
            // its
            // NULL argument; the root remains mapped until every worker is
            // joined.
            unsafe {
                pthread_create(
                    thread,
                    core::ptr::null(),
                    concurrent_worker,
                    core::ptr::null_mut(),
                )
            },
            0,
        );
    }
    for thread in threads {
        // SAFETY: each id came from successful creation above and is joined
        // once here; a NULL result slot is explicitly supported by
        // pthread_join.
        assert_eq!(unsafe { pthread_join(thread, core::ptr::null_mut()) }, 0);
    }
    error_once();

    print(b"DLOPEN_THREADS_OK\n");
}

fn exchange_file(path: &[u8], bytes: &mut [u8], writing: bool) {
    let flags = if writing { 512 | 1024 | 1 } else { 0 };
    let path = CStr::from_bytes_with_nul(path).expect("fixture C path");
    // SAFETY: path is a borrowed C string live through open; the create-mode
    // argument has the required promoted integer representation.
    let fd = unsafe { open(path.as_ptr(), flags, 0o644i32) };
    assert!(fd >= 0);
    let count = if writing {
        // SAFETY: fd is owned by this call and bytes is readable for its length
        // until the synchronous write returns.
        unsafe { write(fd, bytes.as_ptr(), bytes.len()) }
    } else {
        // SAFETY: fd is open and bytes supplies an exclusive writable range
        // of exactly the advertised length through the synchronous read.
        unsafe { read(fd, bytes.as_mut_ptr(), bytes.len()) }
    };
    assert_eq!(count, bytes.len() as isize);
    // SAFETY: this call owns fd from the successful open above and closes it
    // once, after completing every borrowed-buffer operation.
    assert_eq!(unsafe { close(fd) }, 0);
}

fn holding_app() {
    let handle = load(b"libdl_plugin.so.1\0", NOW);
    let mut bytes = (handle as usize).to_ne_bytes();
    exchange_file(b"/dlopen-handle\0", &mut bytes, true);
    loop {
        // SAFETY: the static path is terminated and stays readable through
        // open; supplying the optional scalar mode is valid for all flags.
        let fd = unsafe { open(b"/dlopen-release\0".as_ptr().cast(), 0, 0o644i32) };
        if fd >= 0 {
            // SAFETY: fd is the owned descriptor just returned by open.
            unsafe { close(fd) };
            break;
        }
        pause(10_000);
    }
    // SAFETY: dl_plugin_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(handle, b"dl_plugin_next\0") }, 1);
    assert_eq!(close_object(handle), 0);
    print(b"DLOPEN_OWNER_OK\n");
}

fn foreign_app() {
    let mut bytes = [0u8; core::mem::size_of::<usize>()];
    exchange_file(b"/dlopen-handle\0", &mut bytes, false);
    let foreign = usize::from_ne_bytes(bytes) as *mut c_void;
    assert!(lookup_symbol(foreign, Some(b"dl_plugin_value\0")).is_null());
    error_once();
    assert_eq!(close_object(foreign), -1);
    error_once();
    let own = load(b"libdl_plugin.so.1\0", NOW);
    assert_ne!(own, foreign);
    // SAFETY: dl_plugin_next is the known C fn() -> usize export;
    // the open token or retained namespace pins its code through this call.
    assert_eq!(unsafe { value(own, b"dl_plugin_next\0") }, 1);
    assert_eq!(close_object(own), 0);
    print(b"DLOPEN_FOREIGN_OK\n");
}

/// # Safety
/// When argc > 1, argv must name at least argc initialized, aligned pointer
/// slots. Each inspected argument must be non-null, readable through its NUL
/// and immutable throughout this call. The runtime must retain these arrays
/// and strings in the application's start storage until main returns.
// SAFETY: the startup ABI supplies the caller-owned argument storage; this
// entry only reads argv[1] when argc > 1 and does not retain a borrowed
// pointer.
#[no_mangle]
pub unsafe extern "C" fn main(
    argc: c_int,
    argv: *const *const c_char,
    _: *const *const c_char,
) -> c_int {
    if argc > 1 {
        assert!(!argv.is_null());
        // SAFETY: argc > 1 indexes the runtime's initialized argv array;
        // that pinned array remains live and immutable through main.
        let argument = unsafe { *argv.add(1) };
        assert!(!argument.is_null());
        // SAFETY: the runtime provides a terminated string, so even an
        // empty argument contains a readable first byte (its NUL).
        let mode = unsafe { *argument };
        match mode as u8 {
            b'h' => {
                holding_app();
                return 0;
            }
            b'f' => {
                foreign_app();
                return 0;
            }
            b'e' => {
                EXIT_MODE.store(1, Ordering::SeqCst);
                let handle = load(b"libdl_plugin.so.1\0", NOW);
                // SAFETY: dl_plugin_value is the known C fn() -> usize export;
                // the open token or retained namespace pins its code through
                // this call.
                assert_eq!(unsafe { value(handle, b"dl_plugin_value\0") }, 42);
                // SAFETY: dl_plugin_set_key is the known C fn() -> usize
                // export;
                // the open token or retained namespace pins its code through
                // this call.
                assert_eq!(unsafe { value(handle, b"dl_plugin_set_key\0") }, 1);
                let nested = load(b"libdl_nested.so.1\0", NOW);
                // SAFETY: dl_nested_value is the known C fn() -> usize export;
                // the open token or retained namespace pins its code through
                // this call.
                assert_eq!(unsafe { value(nested, b"dl_nested_value\0") }, 41);
                print(b"DLOPEN_EXIT_OPEN\n");
                // Outstanding runtime handles must be finalized at exit.
                return 0;
            }
            _ => {}
        }
    }

    failures_and_startup();
    reference_counts();
    global_scope();
    recursive_and_tls();
    concurrent_and_errors();
    print(b"DLOPEN_ALL_OK\n");
    0
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    struct Writer;
    impl core::fmt::Write for Writer {
        fn write_str(&mut self, message: &str) -> core::fmt::Result {
            print(message.as_bytes());
            Ok(())
        }
    }
    use core::fmt::Write;
    let _write_result = writeln!(Writer, "DLOPEN_FAIL {info}");
    loop {}
}
