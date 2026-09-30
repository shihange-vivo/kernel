// NEWLINE-TIMEOUT: 60
// ASSERT-SUCC: Dynamic sequence test ended
// ASSERT-FAIL: Backtrace in Panic.*
// ASSERT-FAIL: ASSERTION FAILED.*
// COUNT: DSO_LOAD path=/system/lib/libc\.so\.1 == 1
// COUNT: DSO_REUSE path=/system/lib/libc\.so\.1 == 4
// COUNT: DSO_FINI path=/system/lib/libc\.so\.1 == 0
// COUNT: DSO_UNLOAD path=/system/lib/libc\.so\.1 == 0
// COUNT: APP_LAUNCHED handle=.* path=/apps/hello/app\.elf == 1
// COUNT: APP_LAUNCHED handle=.* path=/apps/multi/app\.elf == 1
// COUNT: APP_LAUNCHED .*scope_bad.* == 0
// COUNT: APP_LAUNCHED handle=.* path=/apps/cycle_demo/app\.elf == 1
// COUNT: APP_LAUNCHED handle=.* path=/apps/tls_demo/app\.elf == 1
// COUNT: APP_REAP handle=.* private_images=1 imported_dsos=1 == 1
// COUNT: APP_REAP handle=.* private_images=4 imported_dsos=1 == 2
// COUNT: APP_REAP handle=.* private_images=3 imported_dsos=1 == 1
// COUNT: application prepare: link application failed: LoadError \{ stage: LinkRelocate.* == 1
// COUNT: NS_LOAD path=/apps/multi/lib/libfoo\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/multi/lib/libbar\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/multi/lib/libcommon\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/cycle_demo/lib/libcycle_a\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/cycle_demo/lib/libcycle_b\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/cycle_demo/lib/libcommon\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/tls_demo/lib/libfoo\.so\.1 == 1
// COUNT: NS_LOAD path=/apps/tls_demo/lib/libbar\.so\.1 == 1
// COUNT: hello dynamic app == 1
// COUNT: multi: foo=42 bar=80 == 1
// COUNT: cycle: value=82 a_ctor=1 b_ctor=1 == 1
// COUNT: tls: a_foo=7 a_bar=7 b_foo=13 b_bar=13 repeat=1 == 1
// COUNT: CONSOLE_RECORD value=complete == 16
// COUNT: ^CONSOLE_STDOUT complete == 16
// COUNT: ^CONSOLE_BUFFERED_BEGIN x{2048} CONSOLE_BUFFERED_END\r?$ == 1
// COUNT: CONSOLE_BUFFERED_AFTER == 1

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(dynamic_sequence_test_runner)]
#![reexport_test_harness_main = "dynamic_sequence_test_main"]

//! Run different dynamic ELF closures sequentially in one runtime. This
//! complements the isolated demo tests by checking shared-system-DSO reuse,
//! private SONAME isolation and rollback after a rejected application.

extern crate alloc;
extern crate rsrt;

use alloc::vec::Vec;
use blueos::application::{runtime, service::ApplicationService};
use blueos_test_macro::test;
use core::sync::atomic::{AtomicUsize, Ordering};
use librs::pthread;
use semihosting::println;

const CONSOLE_ROUNDS: usize = 16;

#[cfg(smp)]
static CONSOLE_DONE: AtomicUsize = AtomicUsize::new(0);

struct ConsoleProbe;

impl core::fmt::Display for ConsoleProbe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(smp)]
        {
            // Formatting has already emitted the record prefix. Give a
            // concurrent stdout writer time to try to insert output here.
            // Do not wait for that thread while local interrupts are masked.
            let deadline = blueos::time::now() + core::time::Duration::from_millis(20);
            while blueos::time::now() < deadline {
                core::hint::spin_loop();
            }
        }
        f.write_str("complete")
    }
}

fn write_console_marker() {
    let message = b"CONSOLE_STDOUT complete\n";
    assert_eq!(
        blueos::vfs::syscalls::write(1, message.as_ptr(), message.len()),
        message.len() as isize
    );
}

#[test]
fn console_buffered_writes_make_progress() {
    // Exceed the software FIFO capacity, exercising its blocking drain/retry
    // path. The following log must not overtake any bytes still queued.
    let mut message = b"CONSOLE_BUFFERED_BEGIN ".to_vec();
    message.resize(message.len() + 2048, b'x');
    message.extend_from_slice(b" CONSOLE_BUFFERED_END\n");
    assert_eq!(
        blueos::vfs::syscalls::write(1, message.as_ptr(), message.len()),
        message.len() as isize
    );
    log::info!("CONSOLE_BUFFERED_AFTER");
}

#[test]
fn console_records_and_stdout_writes_are_complete() {
    #[cfg(smp)]
    let writer = blueos::thread::spawn(|| {
        for _ in 0..CONSOLE_ROUNDS {
            write_console_marker();
        }
        CONSOLE_DONE.store(1, Ordering::Release);
        let _ = blueos::sync::atomic_wake(&CONSOLE_DONE, 1);
    })
    .expect("spawn console writer");

    for _ in 0..CONSOLE_ROUNDS {
        log::info!("CONSOLE_RECORD value={}", ConsoleProbe);
        #[cfg(not(smp))]
        write_console_marker();
    }

    #[cfg(smp)]
    {
        let deadline = blueos::time::now() + core::time::Duration::from_secs(5);
        while CONSOLE_DONE.load(Ordering::Acquire) == 0 {
            assert!(
                blueos::time::now() < deadline,
                "stdout writer did not finish"
            );
            let _ =
                blueos::sync::atomic_wait(&CONSOLE_DONE, 0, blueos::time::Tick::from_millis(50));
        }
        drop(writer);
    }
}

fn launch_and_wait(service: &ApplicationService, path: &str) {
    let mut argv = Vec::new();
    argv.push(path.as_bytes().to_vec());
    let handle = service
        .spawn(path, argv, Vec::new())
        .expect("spawn sequence app");

    static WAIT_ATOM: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..600 {
        if !service.manager().contains(handle) {
            return;
        }
        let _ = blueos::sync::atomic_wait(
            &WAIT_ATOM,
            WAIT_ATOM.load(Ordering::Acquire),
            blueos::time::Tick::from_millis(50),
        );
    }
    panic!("sequence app was not reaped within the wait bound");
}

fn reject_scope_bad(service: &ApplicationService) {
    let path = "/apps/scope_bad/app.elf";
    let mut argv = Vec::new();
    argv.push(path.as_bytes().to_vec());
    assert!(
        service.spawn(path, argv, Vec::new()).is_err(),
        "weak-call application must be rejected"
    );
}

#[test]
fn different_elf_closures_are_isolated() {
    let service = runtime::init();

    // Establish the shared libc instance with the simplest root-only image.
    launch_and_wait(service, "/apps/hello/app.elf");

    // These later bundles deliberately reuse private SONAMEs such as
    // libfoo.so.1, libbar.so.1 and libcommon.so.1. Each must resolve within
    // its own application namespace rather than reusing an earlier image.
    launch_and_wait(service, "/apps/multi/app.elf");

    // A failed relocation transaction must not poison the registry, slot
    // allocator or subsequent private namespace construction.
    reject_scope_bad(service);
    launch_and_wait(service, "/apps/cycle_demo/app.elf");
    launch_and_wait(service, "/apps/tls_demo/app.elf");
}

#[no_mangle]
pub fn dynamic_sequence_test_runner(tests: &[&dyn Fn()]) {
    println!("Dynamic sequence test started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("Dynamic sequence test ended");
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    blueos::application::seed::install();
    pthread::register_my_posix_tcb();
    dynamic_sequence_test_main();
    0
}
