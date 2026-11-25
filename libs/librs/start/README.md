# Native standalone ELF startup

`crt1` is the application entry object for RV32, RV64 and AArch64. It reads
`argc` and `argv` from the native ELF initial stack and calls:

```text
__libc_start_main(main, argc, argv, NULL, NULL, rtld_fini, initial_sp)
```

The RISC-V entry establishes the application's `gp`. Both entries preserve the
optional `rtld_fini` register, keep the initial stack aligned and trap if the
non-returning libc entry unexpectedly returns. Relocation is already complete
before `_start`; the CRT does not load dependencies or relocate itself.

## Build an application

```gn
import("//build/templates/static_pie_app.gni")

static_pie_app("my_app") {
  sources = [ "src/main.rs" ]
}
```

The Rust root links librs explicitly, then uses an ordinary Rust entry:

```rust
extern crate librs;

fn main() {
    let worker = std::thread::spawn(|| vec![42; 32]);
    assert_eq!(worker.join().unwrap().len(), 32);
}
```

The template supplies `crt1` and `librs_swi`, PIC code, static PIE linking and
an explicit `_start` entry. The CRT archive is retained through `-u _start`.
It uses the board's application linker configuration, without its kernel
linker script or `rsrt`. Additional dependencies must also support PIC.
`std` supplies Rust allocation and panic support. A `no_std` root supplies its
own allocator and panic handler. The `librs_swi` target enables the
`standalone_elf` feature for `__libc_start_main`, `exit`, `atexit`, `environ`
and `getauxval`. Firmware links `librs` and enters through
`rsrt` and `__librs_start_main()`.

## Load and finish

`CONFIG_THREAD_GROUP` defaults to `n`, which selects the Process resource model.
Set `thread_group=true` in GN to select thread groups for boot applications
and children created through `CreateThread`. With `thread_group=false` (the GN
default), the board defconfig and other Kconfig inputs select the model.
Loader integration tests that start standalone ELFs enable thread groups in
their own GN toolchain configuration.
VFS remains optional, and `loader_backend` only selects native ELF support.
Image loading and `StartupStorage` construction remain available in Process
builds, but the current ELF execution bridge requires thread groups.
Import `ThreadGroup`, its state/error/exit types and `StandardIo` directly from
`blueos::thread_group`; the loader module exports its loading and startup APIs.

For a complete launch, call unsafe `loader::run(reader, &request)` with any
`ElfReader`. This entry requires thread groups and works with or without VFS.
The caller opens files and constructs a `VfsElfReader`, or supplies memory
through `SliceElfReader`; there is no separate path-based run entry.
`RunRequest::execfn` optionally supplies the program name for `AT_EXECFN` and
does not select the image source. `RunRequest` and `RunError` remain available
in either resource model; the current `run` function and its thread-group
dependencies are conditionally compiled. The current `RunRequest::stdio`
field requires both thread groups and VFS.

The kernel loads the file through `loader::load_image`, constructs
`StartupStorage` and converts it using unsafe `into_thread_group(None)` when
VFS is enabled, or `into_thread_group()` otherwise. The operation requires
trusted native code and all image users to remain within
the thread group's lifetime. `ThreadGroup::start()` schedules its main thread.
With VFS enabled, members share the group's descriptor table. Unowned kernel
threads have no application descriptor table.
Pass `Some(&stdio)` at creation to supply standard streams instead of opening
the default console. Keep the supplied streams open until all groups using
them have finished, then close them as their owner. The table is initialized
before the main thread is registered. `start()` schedules the thread.

Libc initializes the image, calls Rust's generated C `main` wrapper, waits for
cooperative child cleanup and executes `atexit`/finalizers. The thread group's
owner releases the image after all member cleanup. `ThreadGroup::wait()` then
reports normal status or aborted execution. Child threads must join or detach
and be able to finish without the main thread running.

Post-retirement callbacks only release resources, such as thread stack storage.
They run on a shared kernel worker without the retired member's identity, TLS
or descriptor table. Pass any required resource handles explicitly; do not wait
for group members or run application finalizers in these callbacks.

Applications and libraries must release their malloc-family allocations
explicitly. Thread-group exit does not track or reclaim those allocations.

`std_app` exercises this production CRT with a normal Rust `fn main`, environment
access, heap growth/zeroing, a std thread and its TLS destructor, finalization
and a nonzero `ExitCode`. `runtime_app` retains an independent test entry to
exercise libc's optional legacy init/fini arguments. The raw `startup_app`
checks the initial stack independently of libc.

The current BlueOS Rust std sources select an empty `std::env::args()` iterator.
The CRT passes native arguments to libc and Rust's generated wrapper, and the
fixture checks them in its constructor; exposing them through `std::env::args()`
requires a separate toolchain update. `std::env::var()` works through librs.
This standalone path uses BlueOS syscalls and its libc implementation; it is
not an assertion of Linux/glibc binary compatibility.

## Open a shared library at runtime

With VFS, thread groups and the dynamic linker enabled, the host can launch a
trusted ELF through `blueos::loader::run_linked_from_path()`. The application
then uses `dlopen`, `dlsym`, `dlclose` and `dlerror` from `librs::dlfcn`.
Explicit paths use VFS path resolution, bare library names use
the executable's directory, and a dependency name uses its requester's directory.

The supported scope is `RTLD_LOCAL`. Both `RTLD_NOW` and `RTLD_LAZY` resolve
relocations at open time. `dlopen(NULL, RTLD_NOW)` opens the startup scope.
`RTLD_GLOBAL` reports an unsupported-mode error. The opening thread runs the
constructors before receiving its handle. Each successful open can be closed
independently. Mappings remain owned by the thread group through finalization,
so closing and reopening a library preserves the instance and its static data.

The trusted flat launcher supplies native loader entry points through
`AT_BLUEKERNEL_DYNAMIC_LINKER`. The group runtime links, calls constructors,
and publishes the result within one native call. On group exit the same runtime
executes the published libraries' finalizers before the startup graph's
finalizers run. The application only uses the librs interfaces above.
