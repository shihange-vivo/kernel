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

#![no_main]
#![no_std]

use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::{c_char, c_int, c_void, CStr},
    ptr,
};
use librs::{
    dlfcn::{dlclose, dlerror, dlopen, dlsym, RTLD_GLOBAL, RTLD_LAZY, RTLD_NOW},
    stdio::{fclose, feof, ferror, fopen, fread, fwrite},
};

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut memory = ptr::null_mut();
        let result = unsafe {
            librs::stdlib::malloc::posix_memalign(
                &raw mut memory,
                layout.align().max(size_of::<usize>()),
                layout.size(),
            )
        };
        if result == 0 {
            memory.cast()
        } else {
            ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, memory: *mut u8, _layout: Layout) {
        unsafe { librs::stdlib::malloc::free(memory.cast()) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

unsafe extern "C" {
    fn linked_value() -> c_int;
    static linked_data: c_int;
}

#[cfg(linked_startup_graph)]
unsafe extern "C" {
    fn chain_plugin_value() -> c_int;
    fn cycle_a_call_b() -> c_int;
}

#[unsafe(no_mangle)]
pub extern "C" fn linked_choice() -> c_int {
    2
}

#[unsafe(no_mangle)]
pub extern "C" fn record_event(event: u8) {
    // The DSO calls back into the root's libc after startup initialized it.
    let mode = unsafe { librs::stdlib::getenv(c"LINK_TEST".as_ptr()) };
    assert!(!mode.is_null());
    assert_eq!(librs::unistd::write(1, &raw const event, 1), 1);
    // SAFETY: getenv returned a live NUL-terminated environment string.
    let mode = unsafe { CStr::from_ptr(mode) };
    if (event == b'D' && mode == c"abort") || (event == b'L' && mode == c"runtime-abort") {
        unsafe { librs::startup::exit(19) };
    }
    if event == b'L' && mode == c"runtime" {
        expect_busy_open();
        // Keep the first open inside its constructor while a peer tries it.
        let mut child = 0;
        assert_eq!(
            librs::pthread::pthread_create(
                &raw mut child,
                ptr::null(),
                busy_open_worker,
                ptr::null_mut()
            ),
            0
        );
        assert_eq!(librs::pthread::pthread_join(child, ptr::null_mut()), 0);
    }
}

fn expect_busy_open() {
    expect_open_error(
        c"linked-plugin.so",
        RTLD_NOW,
        c"the thread group is loading or finalizing a library",
    );
}

extern "C" fn busy_open_worker(_argument: *mut c_void) -> *mut c_void {
    expect_busy_open();
    ptr::null_mut()
}

type Init = extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

extern "C" fn preinit(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    record_event(b'P');
}

extern "C" fn init(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    record_event(b'I');
}

extern "C" fn fini() {
    record_event(b'F');
}

#[used]
#[unsafe(link_section = ".preinit_array")]
static PREINIT: Init = preinit;

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: Init = init;

#[used]
#[unsafe(link_section = ".fini_array")]
static FINI: extern "C" fn() = fini;

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    let mode = unsafe { librs::stdlib::getenv(c"LINK_TEST".as_ptr()) };
    // SAFETY: a non-null getenv result points to the current environment string.
    let mode = if mode.is_null() {
        c""
    } else {
        unsafe { CStr::from_ptr(mode) }
    };
    let with_plugin = mode == c"plugin";
    assert_eq!(unsafe { linked_data }, if with_plugin { 22 } else { 21 });
    record_event(b'M');
    match mode.to_bytes() {
        #[cfg(linked_startup_graph)]
        b"startup-graph" => {
            // SAFETY: both imports name live C functions of the startup graph.
            unsafe {
                assert_eq!(chain_plugin_value(), 23);
                assert_eq!(cycle_a_call_b(), 16);
            }
        }
        b"runtime" | b"runtime-abort" => exercise_dlfcn(),
        b"runtime-chain" => {
            exercise_dependency_chain();
            return 0;
        }
        b"runtime-cycle" => {
            exercise_dependency_cycle();
            return 0;
        }
        b"runtime-retry" => exercise_plugin_retry(),
        b"runtime-scope" => exercise_scope(),
        b"runtime-holding" => exercise_handle_owner(),
        b"runtime-peer" => exercise_handle_peer(),
        b"runtime-small-stack" => {
            exercise_small_stack();
            return 21;
        }
        _ => {}
    }
    unsafe { linked_value() }
}

fn exercise_dependency_chain() {
    let plugin = open_fixture(c"liblinked_chain_plugin.so", RTLD_NOW);
    for (name, expected) in [
        (c"chain_plugin_value", 23),
        (c"chain_middle_value", 6),
        (c"chain_peer_value", 13),
        (c"chain_leaf_value", 3),
        (c"chain_choice", 4),
    ] {
        // SAFETY: the named fixture export has signature int(void).
        assert_eq!(
            unsafe { call_fixture_value(symbol(plugin, name)) },
            expected
        );
    }
    assert_eq!(dlclose(plugin), 0);
    record_event(b'R');
}

fn exercise_dependency_cycle() {
    let a = open_fixture(c"liblinked_cycle_a.so", RTLD_NOW);
    let b = open_fixture(c"liblinked_cycle_b.so", RTLD_NOW);
    for (name, expected) in [(c"cycle_a_call_b", 16), (c"cycle_b_call_a", 26)] {
        let from_a = symbol(a, name);
        let from_b = symbol(b, name);
        assert_eq!(from_a, from_b);
        // SAFETY: the named fixture export has signature int(void).
        assert_eq!(unsafe { call_fixture_value(from_a) }, expected);
    }
    expect_symbol_error(a, c"missing_cycle_symbol", c"dynamic symbol not found");
    assert_eq!(dlclose(a), 0);
    assert_eq!(dlclose(b), 0);
    record_event(b'R');
}

fn exercise_plugin_retry() {
    let path = c"/linked-fixtures/linked-plugin.so";
    let name = c"linked_value";
    let startup = open_fixture(c"liblinked_test_dso.so", RTLD_NOW);
    let value = symbol(startup, name);
    // SAFETY: linked_value has signature int(void), and its handle stays open.
    assert_eq!(unsafe { call_fixture_value(value) }, 42);

    expect_open_error(
        path,
        RTLD_NOW,
        c"cannot link the library or its dependencies",
    );
    expect_open_error(
        path,
        RTLD_LAZY,
        c"cannot link the library or its dependencies",
    );
    assert_eq!(symbol(startup, name), value);
    // SAFETY: the startup library and its original handle are still live.
    assert_eq!(unsafe { call_fixture_value(value) }, 42);
    record_event(b'E');

    copy_fixture(c"/linked-fixtures/linked-plugin-retry.so", path);
    let plugin = open_fixture(path, RTLD_NOW);
    assert_eq!(symbol(plugin, name), value);
    // SAFETY: value still identifies the startup library's linked_value.
    assert_eq!(unsafe { call_fixture_value(value) }, 44);
    assert_eq!(dlclose(plugin), 0);
    assert_eq!(dlclose(startup), 0);
    record_event(b'R');
}

fn exercise_scope() {
    let handle = open_fixture(c"liblinked_scope.so", RTLD_NOW);
    let check = symbol(handle, c"scope_check");
    let choice = symbol(handle, c"linked_choice");
    let tick = symbol(handle, c"scope_tick");
    // SAFETY: these three exported functions have signature int(void).
    unsafe {
        assert_eq!(call_fixture_value(check), 1);
        assert_eq!(call_fixture_value(choice), 33);
        assert_eq!(call_fixture_value(tick), 1122);
    }
    assert_eq!(linked_choice(), 2);
    expect_symbol_error(handle, c"scope_hidden", c"dynamic symbol not found");
    assert!(symbol(handle, c"missing_parent_symbol").is_null());
    let mut child = 0;
    assert_eq!(
        librs::pthread::pthread_create(&raw mut child, ptr::null(), scope_worker, handle),
        0
    );
    assert_eq!(librs::pthread::pthread_join(child, ptr::null_mut()), 0);
    expect_dlerror(c"dynamic symbol not found");
    // SAFETY: the original handle is still open and the signature is unchanged.
    assert_eq!(unsafe { call_fixture_value(tick) }, 1223);

    // The second file has the same SONAME, but a distinct key and TLS control.
    let alias = open_fixture(c"alternate-scope.so", RTLD_NOW);
    let alias_tick = symbol(alias, c"scope_tick");
    assert_ne!(alias_tick, tick);
    // SAFETY: the second copy exports the same int(void) function.
    assert_eq!(unsafe { call_fixture_value(alias_tick) }, 1124);
    assert_eq!(dlclose(alias), 0);
    // Leave the first handle open. Group exit still finalizes all of the DSOs.
    record_event(b'R');
}

extern "C" fn scope_worker(handle: *mut c_void) -> *mut c_void {
    assert!(dlerror().is_null());
    let tick = symbol(handle, c"scope_tick");
    // SAFETY: the parent keeps the group handle open through the join.
    unsafe {
        assert_eq!(call_fixture_value(tick), 1122);
        assert_eq!(call_fixture_value(tick), 1223);
    }
    expect_symbol_error(handle, c"missing_child_symbol", c"dynamic symbol not found");
    ptr::null_mut()
}

fn exercise_handle_owner() {
    let plugin = open_fixture(c"linked-plugin.so", RTLD_NOW);
    let data = symbol(plugin, c"linked_data");
    assert!(!data.is_null());
    assert_eq!(unsafe { linked_data }, 22);
    publish_words(c"/linked-fixtures/handle", &[plugin.addr(), data.addr()]);
    assert_eq!(wait_for_words::<1>(c"/linked-fixtures/release"), [1]);
    assert_eq!(symbol(plugin, c"linked_data"), data);
    assert_eq!(unsafe { linked_data }, 22);
    assert_eq!(dlclose(plugin), 0);
    record_event(b'R');
}

fn exercise_handle_peer() {
    let [foreign, foreign_data] = wait_for_words(c"/linked-fixtures/handle");
    let foreign = ptr::without_provenance_mut(foreign);
    expect_symbol_error(foreign, c"linked_data", c"invalid dynamic library handle");
    assert_eq!(dlclose(foreign), -1);
    expect_dlerror(c"invalid dynamic library handle");

    let local = open_fixture(c"linked-plugin.so", RTLD_NOW);
    assert_ne!(local, foreign);
    let data = symbol(local, c"linked_data");
    assert!(!data.is_null());
    assert_ne!(data.addr(), foreign_data);
    assert_eq!(unsafe { linked_data }, 22);
    assert_eq!(dlclose(local), 0);
    publish_words(c"/linked-fixtures/release", &[1]);
    record_event(b'R');
}

fn publish_words(path: &CStr, words: &[usize]) {
    // SAFETY: the path is NUL-terminated and words is readable for the write.
    unsafe {
        let file = fopen(path.as_ptr(), c"wb".as_ptr());
        assert!(!file.is_null());
        assert_eq!(
            fwrite(words.as_ptr().cast(), size_of::<usize>(), words.len(), file),
            words.len()
        );
        assert_eq!(fclose(file), 0);
    }
}

fn wait_for_words<const N: usize>(path: &CStr) -> [usize; N] {
    let mut words = [0; N];
    for _ in 0..2000 {
        // SAFETY: the path and the aligned writable buffer live through the read.
        unsafe {
            let file = fopen(path.as_ptr(), c"rb".as_ptr());
            if !file.is_null() {
                let read = fread(words.as_mut_ptr().cast(), size_of::<usize>(), N, file);
                assert_eq!(fclose(file), 0);
                if read == N {
                    return words;
                }
            }
        }
        assert_eq!(librs::time::usleep(1_000), 0);
    }
    panic!("timed out waiting for the other loaded application");
}

fn copy_fixture(source: &CStr, destination: &CStr) {
    // SAFETY: the strings are NUL-terminated and buffers and streams stay
    // valid through each call. The test uses two distinct paths in tmpfs.
    unsafe {
        let input = fopen(source.as_ptr(), c"rb".as_ptr());
        assert!(!input.is_null());
        let output = fopen(destination.as_ptr(), c"wb".as_ptr());
        assert!(!output.is_null());
        let mut bytes = [0u8; 256];
        loop {
            let count = fread(bytes.as_mut_ptr().cast(), 1, bytes.len(), input);
            if count == 0 {
                break;
            }
            assert_eq!(fwrite(bytes.as_ptr().cast(), 1, count, output), count);
        }
        assert_eq!(ferror(input), 0);
        assert_ne!(feof(input), 0);
        assert_eq!(fclose(input), 0);
        assert_eq!(fclose(output), 0);
    }
}

/// # Safety
/// A non-null address must identify a live fixture function with signature `int(void)`.
unsafe fn call_fixture_value(address: *mut c_void) -> c_int {
    assert!(!address.is_null());
    // SAFETY: the caller guarantees the signature and keeps the mapping alive.
    let value: unsafe extern "C" fn() -> c_int = unsafe { core::mem::transmute(address) };
    unsafe { value() }
}

fn expect_dlerror(expected: &CStr) {
    let error = dlerror();
    assert!(!error.is_null());
    // SAFETY: the libc keeps its diagnostic string live after dlerror().
    assert_eq!(unsafe { CStr::from_ptr(error) }, expected);
    assert!(dlerror().is_null());
}

fn open_fixture(path: &CStr, flags: c_int) -> *mut c_void {
    // SAFETY: path is a live NUL-terminated string.
    let handle = unsafe { dlopen(path.as_ptr(), flags) };
    assert!(!handle.is_null());
    handle
}

fn expect_open_error(path: &CStr, flags: c_int, expected: &CStr) {
    // SAFETY: path is a live NUL-terminated string.
    assert!(unsafe { dlopen(path.as_ptr(), flags) }.is_null());
    expect_dlerror(expected);
}

fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    // SAFETY: name is a live NUL-terminated string, and the runtime validates the handle.
    unsafe { dlsym(handle, name.as_ptr()) }
}

fn expect_symbol_error(handle: *mut c_void, name: &CStr, expected: &CStr) {
    assert!(symbol(handle, name).is_null());
    expect_dlerror(expected);
}

fn exercise_small_stack() {
    expect_open_error(
        c"linked-plugin.so",
        RTLD_NOW,
        c"insufficient memory or stack for dynamic loading",
    );
    // Reusing a startup dependency only needs to create a new handle.
    let existing = open_fixture(c"liblinked_test_dso.so", RTLD_NOW);
    assert_eq!(dlclose(existing), 0);
    assert_eq!(unsafe { linked_data }, 21);
}

fn exercise_dlfcn() {
    // SAFETY: a null path opens the startup symbol scope.
    let main = unsafe { dlopen(ptr::null(), RTLD_NOW) };
    assert!(!main.is_null());
    assert_eq!(
        symbol(main, c"linked_choice").addr(),
        linked_choice as *const () as usize
    );
    assert_eq!(dlclose(main), 0);
    expect_open_error(
        c"linked-plugin.so",
        RTLD_NOW | RTLD_GLOBAL,
        c"dlopen: global visibility is not supported",
    );
    expect_open_error(
        c"/absent-plugin.so",
        RTLD_NOW,
        c"cannot read the library or its dependencies",
    );

    let first = open_fixture(c"linked-plugin.so", RTLD_NOW);
    assert_eq!(unsafe { linked_data }, 22);
    let second = open_fixture(c"/linked-fixtures/./linked-plugin.so", RTLD_LAZY);
    let data = symbol(first, c"linked_data");
    assert!(!data.is_null());
    // SAFETY: the open fixture exports linked_data as a C int.
    assert_eq!(unsafe { data.cast::<c_int>().read() }, 22);
    expect_symbol_error(first, c"record_event", c"dynamic symbol not found");
    assert_eq!(dlclose(first), 0);
    expect_symbol_error(first, c"plugin_data", c"invalid dynamic library handle");
    assert_eq!(symbol(second, c"linked_data"), data);
    assert_eq!(dlclose(second), 0);

    let reopened = open_fixture(c"linked-plugin.so", RTLD_NOW);
    assert_eq!(unsafe { linked_data }, 22);
    assert_eq!(dlclose(reopened), 0);
    assert!(dlerror().is_null());
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { librs::startup::exit(127) }
}
