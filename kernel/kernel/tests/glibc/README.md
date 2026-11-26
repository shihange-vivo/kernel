# AArch64 glibc smoke test

`blueos::loader::run_linux_from_path` starts a trusted Linux PIE from the VFS.
It maps the PIE and the absolute interpreter path in `PT_INTERP`, supplies the
initial stack including `AT_BASE` and `AT_RANDOM`, and enters GNU `ld.so`.
The caller provides 16 bytes of entropy and receives the process exit status.
GNU `ld.so` performs relocation, dependency loading and TLS initialization.
Image loading uses the caller's stack. The test uses 16 KiB for the loader
thread and 64 KiB for the application.

This entry uses EL1 and the shared flat address space, with software mapping
permissions and one Linux thread per process. The supported mmap operations
cover private file and anonymous mappings and fixed remapping within an
existing reservation. The process's break uses a separate 1 MiB reservation.

Build the AArch64 Linux glibc tree out of source with an AArch64 Linux
cross-compiler and Linux UAPI headers. Set `GLIBC_BUILD` to the absolute build
directory and run the following from the BlueKernel repository root. The test
links against the same glibc build it stages in QEMU.

```sh
fixtures="$PWD/out/glibc-smoke"
mkdir -p "$fixtures"
aarch64-linux-gnu-strip --strip-debug \
  -o "$fixtures/ld-linux-aarch64.so.1" "$GLIBC_BUILD/elf/ld.so"
aarch64-linux-gnu-strip --strip-debug \
  -o "$fixtures/libc.so.6" "$GLIBC_BUILD/libc.so"
aarch64-linux-gnu-gcc -O0 -fPIE -pie -nostdlib -nostartfiles \
  -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 -Wl,-rpath,/lib \
  -Wl,-z,now -Wl,-z,relro -Wl,-rpath-link,"$GLIBC_BUILD/elf" \
  -o "$fixtures/glibc-hello" \
  "$GLIBC_BUILD/csu/Scrt1.o" "$GLIBC_BUILD/csu/crti.o" \
  kernel/kernel/tests/glibc/hello.c "$GLIBC_BUILD/libc.so" \
  -Wl,--as-needed "$GLIBC_BUILD/elf/ld.so" "$GLIBC_BUILD/csu/crtn.o"

gn gen out/aarch64-glibc \
  --args="board=\"qemu_virt64_aarch64\" build_type=\"debug\" syscall_mode=\"linux_abi\" linux_glibc_smoke_dir=\"$fixtures\""
ninja -C out/aarch64-glibc kernel/kernel:run_unittest
```

Set the GN argument `linux_syscalls_source_dir` to a local Linux 7.0 source
directory to generate syscall numbers from its `scripts/syscall.tbl`.

The test stages the three files in the guest VFS. It runs the PIE twice and
requires exit status 42 both times. The PIE checks the startup stack, native
TLS, its constructor, heap allocation, console output and Linux `ENOSYS`.
