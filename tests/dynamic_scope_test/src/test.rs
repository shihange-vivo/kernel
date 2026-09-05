// NEWLINE-TIMEOUT: 10
// ASSERT-SUCC: Dynamic scope test ended
// ASSERT-FAIL: Backtrace in Panic.*
// ASSERT-FAIL: ASSERTION FAILED.*
// COUNT: DSO_LOAD soname=libscope_sys\.so\.1 == 2
// COUNT: DSO_UNLOAD soname=libscope_sys\.so\.1 == 2
// COUNT: DSO_REUSE soname=libc\.so\.1 == 3
// COUNT: PKG_LOAD soname=libweak\.so\.1 path=/apps/scope_demo/lib/libweak\.so\.1 == 2
// COUNT: PKG_LOAD soname=libstrong\.so\.1 path=/apps/scope_demo/lib/libstrong\.so\.1 == 2
// COUNT: PKG_LOAD soname=libhidden\.so\.1 path=/apps/scope_demo/lib/libhidden\.so\.1 == 2
// COUNT: PKG_LOAD soname=libprotected\.so\.1 path=/apps/scope_demo/lib/libprotected\.so\.1 == 2
// COUNT: PKG_LOAD soname=libweakdata\.so\.1 path=/apps/scope_demo/lib/libweakdata\.so\.1 == 2
// COUNT: APP_LAUNCHED handle=.*:1 path=/apps/scope_demo/app\.elf == 1
// COUNT: APP_REAP handle=.*:1 private_images=6 imported_dsos=2 == 1
// COUNT: APP_LAUNCHED handle=.*:2 path=/apps/scope_demo/app\.elf == 1
// COUNT: APP_REAP handle=.*:2 private_images=6 imported_dsos=2 == 1
// COUNT: scope: value=111 fn=1110 hidden=555 hidden_report=999 protected=333 self=444 sys=777 sys_target=42 sys_ctor=1 weakdata=0 == 2
// COUNT: DSO_FINI soname=libscope_sys\.so\.1 == 2
// COUNT: SCOPE_BIND requester=.* name=missing_data provider=none == 2
// COUNT: SCOPE_BIND requester=7 name=sys_target provider=7 == 2
// COUNT: application prepare: link package failed: LoadError \{ stage: LinkRelocate.* == 1
// COUNT: APP_LAUNCHED .*scope_bad.* == 0

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(dynamic_scope_test_runner)]
#![reexport_test_harness_main = "dynamic_scope_test_main"]
#![feature(c_size_t)]

//! C31-a scope/visibility vertical test (§17.2): the frozen application scope
//! decisions, observed through real Thumb ELF artifacts.
//!
//! The scope corpus package (`apps/example/dynamic/scope_demo`) exercises:
//!
//! * strong over weak — libweak (SysV `DT_HASH`) is discovered first, but its
//!   weak `scope_value`/`scope_fn` lose to libstrong's strong definitions;
//! * hidden — libhidden's hidden `hidden_probe` never leaks into the scope
//!   (libstrong's strong one binds; the owner's `hidden_report` reads its own);
//! * protected — libprotected's owner-local `self_value` binding wins over the
//!   root's interposing strong definition;
//! * app interpose — the root's own definitions bind root-first;
//! * system non-interpose — the freshly loaded system DSO's `sys_target`
//!   relocation binds its own definition (SCOPE_BIND requester=7 provider=7)
//!   even though the root defines a same-named symbol;
//! * undefined weak data — `missing_data` binds to zero
//!   (SCOPE_BIND provider=none; the app prints weakdata=0).
//!
//! The negative package (`scope_bad`) carries an undefined weak *function*
//! call: the relocation policy must reject the link and the app must never
//! launch.

extern crate alloc;
extern crate rsrt;

use alloc::vec::Vec;
use blueos::application::seed;
use blueos::application::service::ApplicationService;
use blueos_test_macro::test;
use core::sync::atomic::{AtomicUsize, Ordering};
use librs::pthread;
use semihosting::println;

/// Launch a package and wait (bounded) for the deferred reaper to recycle its
/// slot. Returns the handle whose generation the relaunch assertion compares.
fn launch_and_wait(
    service: &ApplicationService,
    path: &str,
) -> blueos::application::manager::ApplicationHandle {
    let mut argv = Vec::new();
    argv.push(path.as_bytes().to_vec());
    let handle = service
        .spawn(path, argv, Vec::new())
        .expect("spawn scope package");

    // Bounded poll: the reaper scans every REAPER_POLL_MILLIS and the app
    // exits within milliseconds of starting.
    static WAIT_ATOM: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..600 {
        if service.manager().query(handle).is_none() {
            return handle;
        }
        let _ = blueos::sync::atomic_wait(
            &WAIT_ATOM,
            WAIT_ATOM.load(Ordering::Acquire),
            blueos::time::Tick::from_millis(50),
        );
    }
    panic!("package was not reaped within the wait bound");
}

#[test]
fn scope_visibility_vertical() {
    // The boot seed path embedded the corpus artifacts and assembled the
    // service (§18.2); the test runs the same entry point.
    let service = seed::init();

    // The scope corpus package: all bindings are asserted by the checker
    // through the app's printed values and the SCOPE_BIND oracle lines.
    // First launch: loads libscope_sys fresh (constructor runs); after the
    // group exits, the reaper runs the system fini on its worker thread and
    // unloads the instance (§8.5).
    let first = launch_and_wait(service, "/apps/scope_demo/app.elf");
    assert_eq!(first.slot, 1, "shell holds slot 0, package takes slot 1");

    // Second launch: the unloaded slot reloads generation+1 (constructor runs
    // again); the checker asserts the init/fini/unload oracle lines.
    let second = launch_and_wait(service, "/apps/scope_demo/app.elf");
    assert_eq!(first.slot, second.slot, "slot must be recycled");
    assert_ne!(
        first.generation, second.generation,
        "generation must bump on relaunch"
    );

    // The negative package: an undefined weak control-flow target must fail
    // closed at relocation, so the application never launches.
    let mut argv = Vec::new();
    argv.push(b"/apps/scope_bad/app.elf".to_vec());
    assert!(
        service.spawn("/apps/scope_bad/app.elf", argv, Vec::new()).is_err(),
        "weak-call package must be rejected"
    );

    // NOTE: the tls_demo emutls corpus package (§8.7) builds and passes its
    // package check; the runtime driver is deferred until the worker-thread
    // pthread/emutls interaction is diagnosed (a fault inside the libc
    // alloc path on the first sub-thread TLS access).
}

#[no_mangle]
pub fn dynamic_scope_test_runner(tests: &[&dyn Fn()]) {
    println!("Dynamic scope test started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("Dynamic scope test ended");
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    pthread::register_my_posix_tcb();
    dynamic_scope_test_main();
    0
}
