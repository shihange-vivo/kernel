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
extern "C" {
    fn dl_event(tag: usize);
    fn dl_dep_value() -> usize;
    fn pthread_key_create(
        key: *mut u32,
        destructor: Option<extern "C" fn(*mut core::ffi::c_void)>,
    ) -> i32;
    fn pthread_key_delete(key: u32) -> i32;
    fn pthread_setspecific(key: u32, value: *const core::ffi::c_void) -> i32;
}
static mut COUNT: usize = 0;
static mut CALLS: usize = 0;
static mut KEY: u32 = u32::MAX;
extern "C" fn key_fini(_: *mut core::ffi::c_void) {
    // SAFETY: only the exit-mode main thread sets this private KEY; its TSD
    // callback runs on that same thread before the plugin handle is released.
    let key = unsafe { KEY };
    // SAFETY: key is the successfully created scalar pthread key, not a pointer.
    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
    // SAFETY: the same serialized callback owns the only write at teardown.
    unsafe { KEY = u32::MAX };
    // SAFETY: dl_event is the pinned root's extern C fn(usize) callback.
    unsafe { dl_event(6) };
}
#[no_mangle]
pub extern "C" fn dl_plugin_set_key() -> usize {
    assert_eq!(
        // SAFETY: the exit-mode main thread uniquely owns this aligned output
        // slot. key_fini has the C signature and the outstanding plugin handle
        // pins it until thread-local destructors have completed.
        unsafe { pthread_key_create(&raw mut KEY, Some(key_fini)) },
        0
    );
    // SAFETY: successful creation initialized KEY; this fixture has no
    // concurrent reader/writer of the private slot.
    let key = unsafe { KEY };
    assert_eq!(
        // SAFETY: the value is an opaque tag, never dereferenced by key_fini;
        // key belongs to this thread's live pthread-key registration.
        unsafe { pthread_setspecific(key, 1usize as *const core::ffi::c_void) },
        0
    );
    1
}
extern "C" fn init() {
    // SAFETY: this private instance's one constructor finishes before the
    // fixture reads COUNT, and no later callback mutates it.
    unsafe { COUNT += 1 };
    // SAFETY: the retained root exports the matching C event callback.
    unsafe { dl_event(2) };
}
extern "C" fn fini() {
    // SAFETY: the root's matching C callback remains mapped through fini.
    unsafe {
        dl_event(3);
    }
}
#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;
#[used]
#[link_section = ".fini_array"]
static FINI: extern "C" fn() = fini;
#[no_mangle]
pub extern "C" fn dl_plugin_value() -> usize {
    // SAFETY: the retained child exports extern C fn() -> usize, and its
    // dependency lease remains live throughout this consumer's call.
    let value = unsafe { dl_dep_value() };
    value + 1
}
#[no_mangle]
pub extern "C" fn dl_plugin_ctor_count() -> usize {
    // SAFETY: COUNT was initialized before this private instance became
    // callable and the fixture never writes it after constructor completion.
    unsafe { COUNT }
}
#[no_mangle]
pub extern "C" fn dl_plugin_next() -> usize {
    // SAFETY: the fixture calls this export only from its application main
    // thread; concurrent workers exercise the separate emutls DSO instead.
    unsafe {
        CALLS += 1;
        CALLS
    }
}
core::arch::global_asm!(".hidden dl_plugin_hidden");
// Listed in rustc's export script; the fixture link replaces it with SHN_ABS 0.
#[no_mangle]
pub static dl_absolute_zero: usize = 0;
#[no_mangle]
pub extern "C" fn dl_plugin_hidden() -> usize {
    999
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
