// NEWLINE-TIMEOUT: 60
// ASSERT-SUCC: Dynamic scope test ended
// ASSERT-FAIL: Backtrace in Panic.*
// ASSERT-FAIL: ASSERTION FAILED.*
// ASSERT-FAIL: scope: concurrent gate timeout
// ASSERT-FAIL: scope: invalid test gate
// ASSERT-FAIL: scope: null probe failed
// COUNT: scope: null probe rejected == 4
// COUNT: DSO_LOAD path=/system/lib/libscope_sys\.so\.1 == 3
// COUNT: DSO_LOAD path=/system/lib/libc\.so\.1 == 1
// COUNT: DSO_REUSE path=/system/lib/libscope_sys\.so\.1 == 1
// COUNT: DSO_UNLOAD path=/system/lib/libscope_sys\.so\.1 == 3
// COUNT: DSO_FINI path=/system/lib/libscope_sys\.so\.1 == 3
// COUNT: DSO_REUSE path=/system/lib/libc\.so\.1 == 3
// COUNT: LINK_MAP owner=7 soname=- .* == 4
// COUNT: NS_LOAD path=/apps/scope_demo/lib/libweak\.so\.1 == 4
// COUNT: NS_LOAD path=/apps/scope_demo/lib/libstrong\.so\.1 == 4
// COUNT: NS_LOAD path=/apps/scope_demo/lib/libhidden\.so\.1 == 4
// COUNT: NS_LOAD path=/apps/scope_demo/lib/libprotected\.so\.1 == 4
// COUNT: NS_LOAD path=/apps/scope_demo/lib/libweakdata\.so\.1 == 4
// COUNT: APP_LAUNCHED handle=.* path=/apps/scope_demo/app\.elf == 4
// COUNT: APP_REAP handle=.* private_images=6 imported_dsos=2 == 4
// COUNT: scope: value=111 fn=1110 hidden=555 hidden_report=999 protected=333 self=444 sys=777 sys_target=42 sys_ctor=1 weakdata=0 == 4
// COUNT: SCOPE_BIND requester=.* name=missing_data provider=none == 4
// COUNT: SCOPE_BIND requester=7 name=sys_target provider=7 == 3
// COUNT: SCOPE_BIND requester=7 name=strlen provider=1 == 3
// COUNT: LINK_EDGE requester=7 provider=1 == 4

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(dynamic_scope_test_runner)]
#![reexport_test_harness_main = "dynamic_scope_test_main"]

//! scope/visibility end-to-end test: the frozen application scope
//! decisions, observed through real dynamically linked ELF artifacts.
//!
//! The scope corpus bundle (`apps/example/dynamic/scope_demo`) exercises:
//!
//! * strong over weak — libweak (SysV `DT_HASH`) is discovered first, but its
//! weak `scope_value`/`scope_fn` lose to libstrong's strong definitions;
//! * hidden — libhidden's hidden `hidden_probe` never leaks into the scope
//! (libstrong's strong one binds; the owner's `hidden_report` reads its own);
//! * protected — libprotected's owner-local `self_value` binding wins over the
//! root's interposing strong definition;
//! * app interpose — the root's own definitions bind root-first;
//! * system non-interpose — the freshly loaded system DSO's `sys_target`
//! relocation binds its own definition (SCOPE_BIND requester=7 provider=7)
//! even though the root defines a same-named symbol;
//! * undefined weak data — `missing_data` binds to zero
//! (SCOPE_BIND provider=none; the app prints weakdata=0).
//! * reused provider closure — the system-to-libc edge remains in all four
//! link results, while only the three fresh instances need relocation;
//! * atomic concurrent acquisition — two linker workers race the same system
//! closure and share one `libscope_sys` instance;

extern crate alloc;
extern crate rsrt;

use alloc::vec::Vec;
use blueos::{
    application::{runtime, service::ApplicationService},
    scheduler,
    thread::{Builder, Entry, Stack, IDLE},
};
use blueos_test_macro::test;
use core::sync::atomic::{AtomicUsize, Ordering};
use librs::pthread;
use semihosting::println;

#[path = "../../../../example/dynamic/scope_demo/app/test_gate.rs"]
mod test_gate;

mod gate_argument_tests {
    use super::test_gate::{from_argv, TestGate};
    use alloc::{ffi::CString, format};
    use blueos_test_macro::test;
    use core::sync::atomic::AtomicUsize;

    fn decode_address(value: &[u8]) -> TestGate {
        let value = CString::new(value).unwrap();
        let argv = [
            b"scope\0".as_ptr().cast(),
            b"--test-gate\0".as_ptr().cast(),
            value.as_ptr(),
        ];
        // SAFETY: the array and every terminated string outlive this call.
        unsafe { from_argv(3, argv.as_ptr()) }
    }

    #[test]
    fn accepts_the_live_kernel_gate_address_format() {
        let gate = AtomicUsize::new(0);
        let pointer = core::ptr::addr_of!(gate);
        let text = format!("{:x}", pointer as usize);
        assert_eq!(decode_address(text.as_bytes()), TestGate::Address(pointer));
    }

    #[test]
    fn rejects_empty_null_and_malformed_addresses() {
        for text in [
            &b""[..],
            b"0",
            b"0000",
            b"-10",
            b"+10",
            b" 10",
            b"10 ",
            b"0x10",
            b"10junk",
            b"zz",
        ] {
            assert_eq!(decode_address(text), TestGate::Invalid);
        }
    }

    #[test]
    fn rejects_addresses_larger_than_usize() {
        let text = format!("{:x}0", usize::MAX);
        assert_eq!(decode_address(text.as_bytes()), TestGate::Invalid);
    }

    #[test]
    fn rejects_misaligned_addresses() {
        let gate = AtomicUsize::new(0);
        let address = (core::ptr::addr_of!(gate) as usize).checked_add(1).unwrap();
        let text = format!("{address:x}");
        assert_eq!(decode_address(text.as_bytes()), TestGate::Invalid);
    }

    #[test]
    fn checks_argc_and_null_argv_before_access() {
        assert_eq!(
            // SAFETY: zero argc returns before inspecting the NULL array.
            unsafe { from_argv(0, core::ptr::null()) },
            TestGate::NotRequested
        );
        for argc in [-1, 1, 3] {
            assert_eq!(
                // SAFETY: from_argv rejects these NULL/invalid-count cases
                // before dereferencing any array pointer.
                unsafe { from_argv(argc, core::ptr::null()) },
                TestGate::Invalid
            );
        }
    }

    #[test]
    fn rejects_null_gate_argument_pointers() {
        let program = b"scope\0".as_ptr().cast();
        let flag = b"--test-gate\0".as_ptr().cast();
        for argv in [
            [program, core::ptr::null(), core::ptr::null()],
            [program, flag, core::ptr::null()],
        ] {
            // SAFETY: three initialized slots and static C strings remain
            // live; NULL flag/value is rejected before reading its contents.
            assert_eq!(unsafe { from_argv(3, argv.as_ptr()) }, TestGate::Invalid);
        }
    }

    #[test]
    fn ignores_other_arguments_without_decoding_an_address() {
        let argv = [
            b"scope\0".as_ptr().cast(),
            b"other\0".as_ptr().cast(),
            b"ignored\0".as_ptr().cast(),
        ];
        assert_eq!(
            // SAFETY: every slot points into a live static terminated string.
            unsafe { from_argv(3, argv.as_ptr()) },
            TestGate::NotRequested
        );
    }
}

/// Launch an application and wait (bounded) for the deferred reaper to recycle its
/// slot. Returns the handle whose generation the relaunch assertion compares.
fn launch_and_wait(
    service: &ApplicationService,
    path: &str,
) -> blueos::application::manager::ApplicationHandle {
    let mut argv = Vec::new();
    argv.push(path.as_bytes().to_vec());
    let handle = service
        .spawn(path, argv, Vec::new())
        .expect("spawn scope app");

    // Bounded poll: the reaper scans every REAPER_POLL_MILLIS and the app
    // exits within milliseconds of starting.
    static WAIT_ATOM: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..600 {
        if !service.manager().contains(handle) {
            return handle;
        }
        let _ = blueos::sync::atomic_wait(
            &WAIT_ATOM,
            WAIT_ATOM.load(Ordering::Acquire),
            blueos::time::Tick::from_millis(50),
        );
    }
    panic!("application was not reaped within the wait bound");
}

#[test]
fn scope_visibility_vertical() {
    // Boot installed the embedded corpus artifacts and initialized the runtime
    //; this idempotent call retrieves the same service without
    // reseeding the VFS.
    let service = runtime::init().expect("initialize application runtime");

    // The scope corpus application: all bindings are asserted by the checker
    // through the app's printed values and the SCOPE_BIND diagnostic lines.
    // First launch: loads libscope_sys fresh (constructor runs); after the
    // group exits, the reaper runs the system fini on its worker thread and
    // unloads the instance.
    let first = launch_and_wait(service, "/apps/scope_demo/app.elf");
    assert_eq!(first.slot, 0, "the first test app takes slot 0");

    // Second launch: the unloaded slot reloads generation+1 (constructor runs
    // again); the checker asserts the init/fini/unload diagnostic lines.
    let second = launch_and_wait(service, "/apps/scope_demo/app.elf");
    assert_eq!(first.slot, second.slot, "slot must be recycled");
    assert_ne!(
        first.generation, second.generation,
        "generation must bump on relaunch"
    );

    // Two kernel threads now race the same system closure. Besides proving
    // that batch acquisition has no partial-wait deadlock, this exercises a
    // shared Ready instance and the last-user unload path concurrently.
    concurrent_system_closure();
}

/// Two kernel threads spawn the scope app simultaneously: each
/// launches and waits for its group's reap, then signals completion.
/// The two racer threads' bodies: launch the scope app, wait for the
/// reap, then set the completion flag the main thread polls.
extern "C" fn concurrent_launcher(flag: *mut core::ffi::c_void) {
    let done = flag as *const core::sync::atomic::AtomicBool;
    let service = ApplicationService::get().expect("service assembled");
    let mut argv = Vec::new();
    argv.push(b"/apps/scope_demo/app.elf".to_vec());
    // Keep both application leases alive until both spawns return. Without
    // this rendezvous a fast guest can reap the first app before the second
    // worker is scheduled, so the intended concurrent case becomes serial.
    // CONCURRENT_READY is an initialized, aligned static in the shared flat
    // address space. It remains live throughout both application calls; every
    // access to it is atomic. This test is the trusted gate-address producer.
    argv.push(b"--test-gate".to_vec());
    argv.push(alloc::format!("{:x}", core::ptr::addr_of!(CONCURRENT_READY) as usize).into_bytes());
    let handle = service
        .spawn("/apps/scope_demo/app.elf", argv, Vec::new())
        .expect("concurrent spawn");
    CONCURRENT_READY.fetch_add(1, Ordering::AcqRel);
    static WAIT_ATOM: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..600 {
        if !service.manager().contains(handle) {
            // SAFETY: Entry::Posix received a pointer to this launcher's
            // aligned static AtomicBool; only atomic accesses touch it.
            unsafe { (*done).store(true, Ordering::Release) };
            return;
        }
        let _ = blueos::sync::atomic_wait(
            &WAIT_ATOM,
            WAIT_ATOM.load(Ordering::Acquire),
            blueos::time::Tick::from_millis(50),
        );
    }
    panic!("concurrent app was not reaped");
}

static CONCURRENT_READY: AtomicUsize = AtomicUsize::new(0);

fn concurrent_system_closure() {
    const LINKER_WORKER_STACK_SIZE: usize = 64 << 10;
    static DONE_A: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static DONE_B: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static WAIT_ATOM: AtomicUsize = AtomicUsize::new(0);

    CONCURRENT_READY.store(0, Ordering::Release);

    let a = Builder::new(Entry::Posix(
        concurrent_launcher,
        &DONE_A as *const _ as *mut core::ffi::c_void,
    ))
    .set_stack(Stack::from_size(LINKER_WORKER_STACK_SIZE).expect("linker worker stack"))
    .build();
    let b = Builder::new(Entry::Posix(
        concurrent_launcher,
        &DONE_B as *const _ as *mut core::ffi::c_void,
    ))
    .set_stack(Stack::from_size(LINKER_WORKER_STACK_SIZE).expect("linker worker stack"))
    .build();
    let _ = scheduler::queue_ready_thread(IDLE, a);
    let _ = scheduler::queue_ready_thread(IDLE, b);
    while !DONE_A.load(Ordering::Acquire) || !DONE_B.load(Ordering::Acquire) {
        let _ = blueos::sync::atomic_wait(
            &WAIT_ATOM,
            WAIT_ATOM.load(Ordering::Acquire),
            blueos::time::Tick::from_millis(10),
        );
    }
}

#[no_mangle]
pub fn dynamic_scope_test_runner(tests: &[&dyn Fn()]) {
    blueos_dynamic_test_support::start();
    println!("Dynamic scope test started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    blueos_dynamic_test_support::finish();
    println!("Dynamic scope test ended");
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    blueos::application::seed::install();
    pthread::register_my_posix_tcb();
    dynamic_scope_test_main();
    0
}
