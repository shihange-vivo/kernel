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

//! Native ELF initial-stack construction and thread-group handoff.

use crate::thread::Stack;
#[cfg(thread_group)]
use crate::{
    thread::{Builder, CleanupError, Entry},
    thread_group::ThreadGroup,
};
#[cfg(all(enable_vfs, thread_group))]
use crate::{
    thread_group::StandardIo,
    vfs::fd_manager::{FdManager, FileDescriptor},
};
#[cfg(thread_group)]
use alloc::boxed::Box;
use blueos_header::startup::{auxv, DynamicLinker, STACK_ALIGNMENT};
use blueos_loader::{ImageMapping, LoadedImage};
use core::{
    ffi::{c_int, c_void, CStr},
    mem::size_of,
    ptr, slice,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    MissingEntry,
    MissingProgramHeaders,
    InvalidAddress,
    InvalidPageSize,
    TooManyArguments,
    StackTooSmall,
    #[cfg(all(enable_dynamic_linker, thread_group))]
    LifecycleUnavailable,
    #[cfg(thread_group)]
    CleanupUnavailable(CleanupError),
    #[cfg(all(enable_vfs, thread_group))]
    FileTable(crate::error::Error),
}

/// Platform values and strings copied into the new application's stack.
/// `page_size` is the platform's ELF ABI page granularity, not a claim that
/// the flat backend implements page protection. Optional random bytes must
/// come from a suitable entropy source when the selected libc requires them.
pub struct StartupArguments<'a> {
    pub argv: &'a [&'a CStr],
    pub envp: &'a [&'a CStr],
    pub page_size: usize,
    pub execfn: Option<&'a CStr>,
    pub random: Option<&'a [u8; 16]>,
}

/// Owns an image and a stack containing its native ELF startup frame.
/// Strings, pointer arrays and auxiliary data all live in that allocation.
/// Moving the owner preserves every exported address. This is a stack-layout
/// adapter, not a claim of complete Linux/glibc runtime compatibility.
#[must_use = "retain the image and stack until application execution finishes"]
pub struct StartupStorage<A: ImageMapping> {
    image: LoadedImage<A>,
    frame: StartupFrame,
}

#[must_use = "retain the startup stack through application execution"]
pub(super) struct StartupFrame {
    stack: Stack,
    #[cfg(thread_group)]
    entry: usize,
    initial_sp: usize,
    words: usize,
}

impl<A: ImageMapping> StartupStorage<A> {
    pub fn new(
        image: LoadedImage<A>,
        stack: Stack,
        args: StartupArguments<'_>,
    ) -> Result<Self, StartupError> {
        let frame = StartupFrame::new(&image, stack, args, None, None)?;
        Ok(Self { image, frame })
    }

    pub fn image(&self) -> &LoadedImage<A> {
        &self.image
    }

    pub fn initial_sp(&self) -> *const usize {
        self.frame.initial_sp as *const usize
    }

    pub fn initial_words(&self) -> &[usize] {
        // SAFETY: construction initialized this exact frame, retained by self.
        unsafe { slice::from_raw_parts(self.initial_sp(), self.frame.words) }
    }

    /// Prepare an unscheduled thread group. The group retains the image and
    /// the stack through cleanup of every member. Dropping it before start
    /// releases the prepared resources.
    /// With VFS enabled, `stdio` selects the standard streams. None opens
    /// the system console. Applications release their own malloc-family blocks.
    ///
    /// # Safety
    /// The image must be trusted native code in the kernel's address space,
    /// using the ELF initial-stack convention with a non-returning entry.
    /// The cache backend must publish code for all CPUs that can execute it.
    /// Additional threads must join the group through CreateThread, and
    /// pointers into the image or stack must stay within the group's lifetime.
    /// Main coordinates normal exit once children can finish cooperatively.
    #[cfg(thread_group)]
    pub unsafe fn into_thread_group(
        self,
        #[cfg(enable_vfs)] stdio: Option<&StandardIo>,
    ) -> Result<ThreadGroup, StartupError>
    where
        A: Send + 'static,
    {
        // SAFETY: the caller authorizes execution; the group retains self.image.
        unsafe {
            self.frame.into_thread_group(
                self.image,
                #[cfg(enable_vfs)]
                stdio,
            )
        }
    }
}

impl StartupFrame {
    /// A lifecycle payload, when present, must be retained by the owner passed
    /// to `into_thread_group` along with the root and all its dependencies.
    pub(super) fn new(
        image: &LoadedImage<impl ImageMapping>,
        stack: Stack,
        args: StartupArguments<'_>,
        lifecycle: Option<&[usize]>,
        dynamic_linker: Option<&'static DynamicLinker>,
    ) -> Result<Self, StartupError> {
        let entry = image.entry().ok_or(StartupError::MissingEntry)?;
        let entry = usize::try_from(entry.get()).map_err(|_| StartupError::InvalidAddress)?;
        let phdr = image
            .program_headers()
            .ok_or(StartupError::MissingProgramHeaders)?;
        let phdr_address =
            usize::try_from(phdr.address().get()).map_err(|_| StartupError::InvalidAddress)?;
        // The kernel's load_image profile guarantees the native machine and
        // byte order; this additional check catches a foreign word-size table.
        let native_phent = if size_of::<usize>() == 8 { 56 } else { 32 };
        if usize::from(phdr.entry_size()) != native_phent
            || !phdr_address.is_multiple_of(size_of::<usize>())
        {
            return Err(StartupError::InvalidAddress);
        }
        if args.argv.len() > c_int::MAX as usize {
            return Err(StartupError::TooManyArguments);
        }
        if !args.page_size.is_power_of_two() {
            return Err(StartupError::InvalidPageSize);
        }
        let overflow = || StartupError::StackTooSmall;
        let pairs = 7
            + usize::from(args.execfn.is_some())
            + usize::from(args.random.is_some())
            + usize::from(lifecycle.is_some())
            + usize::from(dynamic_linker.is_some());
        let words = args
            .argv
            .len()
            .checked_add(args.envp.len())
            .and_then(|n| n.checked_add(3 + pairs * 2))
            .ok_or_else(overflow)?;
        let mut bytes = words.checked_mul(size_of::<usize>()).ok_or_else(overflow)?;
        for string in args
            .argv
            .iter()
            .chain(args.envp)
            .copied()
            .chain(args.execfn)
        {
            bytes = bytes
                .checked_add(string.to_bytes_with_nul().len())
                .ok_or_else(overflow)?;
        }
        if args.random.is_some() {
            bytes = bytes.checked_add(16).ok_or_else(overflow)?;
        }
        let top = stack.top();
        let sp = top.addr().checked_sub(bytes).ok_or_else(overflow)? & !(STACK_ALIGNMENT - 1);
        if !stack.can_init_at(sp) {
            return Err(overflow());
        }
        // SAFETY: the checked SP is inside the allocation, with room for the
        // context below it and the complete startup payload above it.
        let frame = unsafe { top.sub(top.addr() - sp).cast::<usize>() };
        let initial_sp = frame as usize;
        // SAFETY: every word is initialized before any shared view or
        // application can read it. The original allocation stays owned by stack.
        let frame = unsafe {
            ptr::write_bytes(frame, 0, words);
            slice::from_raw_parts_mut(frame, words)
        };
        let mut payload = top;
        frame[0] = args.argv.len();
        let mut index = 1;
        for string in args.argv {
            frame[index] = unsafe { copy_string(&mut payload, string) };
            index += 1;
        }
        frame[index] = 0;
        index += 1;
        for string in args.envp {
            frame[index] = unsafe { copy_string(&mut payload, string) };
            index += 1;
        }
        frame[index] = 0;
        index += 1;
        let mut push = |key, value| {
            frame[index] = key;
            frame[index + 1] = value;
            index += 2;
        };
        push(auxv::AT_PHDR, phdr_address);
        push(auxv::AT_PHENT, usize::from(phdr.entry_size()));
        push(auxv::AT_PHNUM, usize::from(phdr.count()));
        push(auxv::AT_ENTRY, entry);
        // The kernel enters the root image directly.
        push(auxv::AT_BASE, 0);
        push(auxv::AT_PAGESZ, args.page_size);
        if let Some(name) = args.execfn {
            push(auxv::AT_EXECFN, unsafe { copy_string(&mut payload, name) });
        }
        if let Some(random) = args.random {
            // SAFETY: the byte budget includes these 16 disjoint payload bytes.
            unsafe {
                payload = payload.sub(16);
                ptr::copy_nonoverlapping(random.as_ptr(), payload, 16);
            }
            push(auxv::AT_RANDOM, payload as usize);
        }
        if let Some(lifecycle) = lifecycle {
            push(auxv::AT_BLUEKERNEL_LIFECYCLE, lifecycle.as_ptr() as usize);
        }
        if let Some(dynamic_linker) = dynamic_linker {
            push(
                auxv::AT_BLUEKERNEL_DYNAMIC_LINKER,
                ptr::from_ref(dynamic_linker) as usize,
            );
        }
        push(auxv::AT_NULL, 0);
        debug_assert_eq!(index, words);
        debug_assert!(payload.addr() >= sp + words * size_of::<usize>());
        Ok(Self {
            stack,
            #[cfg(thread_group)]
            entry,
            initial_sp,
            words,
        })
    }

    #[cfg(all(enable_dynamic_linker, thread_group, enable_vfs))]
    pub(super) fn native_arguments(&self, argc: usize) -> [usize; 3] {
        let argv = self.initial_sp + size_of::<usize>();
        let envp = argv + (argc + 1) * size_of::<usize>();
        [argc, argv, envp]
    }

    #[cfg(thread_group)]
    pub(super) unsafe fn into_thread_group<T: Send + 'static>(
        self,
        owner: T,
        #[cfg(enable_vfs)] stdio: Option<&StandardIo>,
    ) -> Result<ThreadGroup, StartupError> {
        #[cfg(enable_vfs)]
        let table = match stdio {
            Some(stdio) => FdManager::from_stdio(
                [
                    stdio.stdin.clone(),
                    stdio.stdout.clone(),
                    stdio.stderr.clone(),
                ]
                .map(FileDescriptor::Borrowed),
            ),
            None => FdManager::with_console().map_err(StartupError::FileTable)?,
        };
        let data = Box::new(EntryData {
            entry: self.entry,
            sp: self.initial_sp,
            _owner: owner,
        });
        let pointer = ptr::from_ref(data.as_ref()).cast_mut().cast::<c_void>();
        let thread = Builder::new(Entry::Posix(bootstrap::<T>, pointer))
            .set_stack(self.stack)
            .set_initial_sp(self.initial_sp)
            .build();
        ThreadGroup::prepare(
            thread,
            data,
            #[cfg(enable_vfs)]
            table,
        )
        .map_err(StartupError::CleanupUnavailable)
    }
}

// Held by the thread group, not by an abandoned bootstrap stack frame.
#[must_use = "the thread group retains this image through all member cleanups"]
#[cfg(thread_group)]
struct EntryData<T> {
    _owner: T,
    entry: usize,
    sp: usize,
}

#[cfg(thread_group)]
extern "C" fn bootstrap<T>(pointer: *mut c_void) {
    // SAFETY: into_thread_group retains this immutable owner through member cleanup.
    let data = unsafe { &*pointer.cast::<EntryData<T>>() };
    // SAFETY: the caller authorizes native execution; the image and the
    // original stack allocation are retained through thread retirement.
    unsafe { enter_elf(data.entry, data.sp) }
}

unsafe fn copy_string(cursor: &mut *mut u8, string: &CStr) -> usize {
    let bytes = string.to_bytes_with_nul();
    // SAFETY: the caller budgets this string in the disjoint payload region.
    unsafe {
        *cursor = cursor.sub(bytes.len());
        ptr::copy_nonoverlapping(bytes.as_ptr(), *cursor, bytes.len());
    }
    *cursor as usize
}

#[cfg(all(thread_group, any(target_arch = "riscv32", target_arch = "riscv64")))]
#[unsafe(naked)]
unsafe extern "C" fn enter_elf(_entry: usize, _sp: usize) -> ! {
    core::arch::naked_asm!("mv t0, a0", "mv sp, a1", "li a0, 0", "li ra, 0", "jr t0");
}

#[cfg(all(thread_group, target_arch = "aarch64"))]
#[unsafe(naked)]
unsafe extern "C" fn enter_elf(_entry: usize, _sp: usize) -> ! {
    core::arch::naked_asm!(
        "mov x16, x0",
        "mov sp, x1",
        "mov x0, xzr",
        "mov x30, xzr",
        "br x16"
    );
}
