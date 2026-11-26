// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
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

use super::Context;
use crate::{
    loader::linux::{LinuxProcess, MAP_ANONYMOUS, PAGE_SIZE},
    process::Process,
    vfs::{self, syscalls, FileAttr, FileOps},
};
use alloc::sync::Arc;
use core::{
    ffi::{c_char, CStr},
    slice,
};
use linux_syscalls::LinuxSysno;

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: usize = 0x1000;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const O_CLOEXEC: usize = 0o2000000;
const O_LARGEFILE: usize = 0o400000;
const O_NONBLOCK: usize = 0o4000;
const MAX_RW_COUNT: usize = i32::MAX as usize & !(PAGE_SIZE - 1);

type Result<T> = core::result::Result<T, i32>;

pub(super) fn dispatch(ctx: &Context, process: &Process, linux: &LinuxProcess) -> isize {
    let Some(nr) = LinuxSysno::from_raw(ctx.nr) else {
        return -(libc::ENOSYS as isize);
    };
    let [a, b, c, d, e, f] = ctx.args;
    let fd = a as i32;
    match nr {
        LinuxSysno::Read => syscalls::read(fd, b as *mut u8, c.min(MAX_RW_COUNT)),
        LinuxSysno::Write => syscalls::write(fd, b as *const u8, c.min(MAX_RW_COUNT)),
        LinuxSysno::Writev => writev(fd, b as *const Iovec, c),
        LinuxSysno::Openat => ret(openat(fd, b, c)),
        LinuxSysno::Close => syscalls::close(fd) as isize,
        LinuxSysno::Lseek => syscalls::lseek(fd, b as i64, c as i32) as isize,
        LinuxSysno::Pread64 => ret(pread(process, fd, b, c, d)),
        LinuxSysno::Fstat => ret(file_attr(process, fd).and_then(|attr| store_stat(b, attr))),
        LinuxSysno::Newfstatat => ret(fstatat(process, fd, b, c, d)),
        LinuxSysno::Faccessat => ret(access(fd, b, c)),
        LinuxSysno::Brk => linux.brk(a) as isize,
        LinuxSysno::Mmap => ret(mmap(process, linux, [a, b, c, d, e, f])),
        LinuxSysno::Munmap => ret(linux.munmap(a, b).map(|()| 0)),
        LinuxSysno::Mprotect => ret(linux.mprotect(a, b, c).map(|()| 0)),
        LinuxSysno::Getpid | LinuxSysno::Gettid => process.pid().0 as isize,
        LinuxSysno::SetTidAddress => {
            linux.set_tid_address(a);
            process.pid().0 as isize
        }
        LinuxSysno::Exit | LinuxSysno::ExitGroup => {
            linux.record_exit(a);
            // The dispatcher releases its Process reference before retiring.
            0
        }
        _ => -(libc::ENOSYS as isize),
    }
}

pub(super) fn is_exit(nr: usize) -> bool {
    nr == LinuxSysno::Exit as usize || nr == LinuxSysno::ExitGroup as usize
}

fn ret(result: Result<usize>) -> isize {
    match result {
        Ok(value) => value as isize,
        Err(errno) => -(errno as isize),
    }
}

fn openat(dir: i32, path: usize, flags: usize) -> Result<usize> {
    let name = pathname(path)?;
    if name.is_empty() {
        return Err(libc::ENOENT);
    }
    check_dir(dir, name)?;
    if flags & !(O_CLOEXEC | O_LARGEFILE | O_NONBLOCK) != 0 {
        return Err(libc::EINVAL);
    }
    let mut vfs_flags = libc::O_RDONLY;
    if flags & O_CLOEXEC != 0 {
        vfs_flags |= libc::O_CLOEXEC;
    }
    if flags & O_NONBLOCK != 0 {
        vfs_flags |= libc::O_NONBLOCK;
    }
    let fd = syscalls::open(name.as_ptr(), vfs_flags, 0);
    if fd < 0 {
        Err(-fd)
    } else {
        Ok(fd as usize)
    }
}

fn file_ops(process: &Process, fd: i32) -> Result<Arc<dyn FileOps>> {
    process
        .fd_manager()
        .irqsave_lock()
        .get_file_ops(fd)
        .ok_or(libc::EBADF)
}

fn file_attr(process: &Process, fd: i32) -> Result<FileAttr> {
    Ok(file_ops(process, fd)?.stat())
}

fn pread(process: &Process, fd: i32, buf: usize, count: usize, offset: usize) -> Result<usize> {
    let ops = file_ops(process, fd)?;
    let file = ops.downcast_ref::<vfs::File>().ok_or(libc::ESPIPE)?;
    if offset > i64::MAX as usize || count > isize::MAX as usize {
        return Err(libc::EINVAL);
    }
    if count == 0 {
        return Ok(0);
    }
    if buf == 0 {
        return Err(libc::EFAULT);
    }
    // SAFETY: trusted ELF code supplies a writable count-byte buffer.
    let buffer = unsafe { slice::from_raw_parts_mut(buf as *mut u8, count) };
    file.read_at(offset as u64, buffer)
        .map_err(|error| -error.to_errno())
}

fn mmap(process: &Process, linux: &LinuxProcess, args: [usize; 6]) -> Result<usize> {
    let [address, len, prot, flags, fd, offset] = args;
    if flags & MAP_ANONYMOUS != 0 {
        return linux.mmap(address, len, prot, flags, None);
    }
    if offset > i64::MAX as usize || !offset.is_multiple_of(PAGE_SIZE) {
        return Err(libc::EINVAL);
    }
    let ops = file_ops(process, fd as i32)?;
    let file = ops.downcast_ref::<vfs::File>().ok_or(libc::ENODEV)?;
    if !file.type_().is_regular_file() {
        return Err(libc::ENODEV);
    }
    linux.mmap(address, len, prot, flags, Some((file, offset as u64)))
}

fn check_dir(dir: i32, name: &CStr) -> Result<()> {
    if dir != AT_FDCWD && !name.to_bytes().starts_with(b"/") {
        return Err(libc::ENOSYS);
    }
    Ok(())
}

fn pathname<'a>(path: usize) -> Result<&'a CStr> {
    if path == 0 {
        return Err(libc::EFAULT);
    }
    // SAFETY: the trusted ELF caller supplies a live NUL-terminated pathname.
    Ok(unsafe { CStr::from_ptr(path as *const c_char) })
}

fn path_attr(name: &CStr) -> Result<FileAttr> {
    let name = name.to_str().map_err(|_| libc::EINVAL)?;
    let entry = vfs::lookup_path(name).ok_or(libc::ENOENT)?;
    Ok(entry.inode().file_attr())
}

fn access(dir: i32, path: usize, mode: usize) -> Result<usize> {
    if mode != 0 {
        return Err(libc::ENOSYS);
    }
    let name = pathname(path)?;
    if name.is_empty() {
        return Err(libc::ENOENT);
    }
    check_dir(dir, name)?;
    path_attr(name).map(|_| 0)
}

fn fstatat(process: &Process, dir: i32, path: usize, out: usize, flags: usize) -> Result<usize> {
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return Err(libc::EINVAL);
    }
    let attr = if flags & AT_EMPTY_PATH != 0 && (path == 0 || pathname(path)?.is_empty()) {
        if dir == AT_FDCWD {
            path_attr(c".")?
        } else {
            file_attr(process, dir)?
        }
    } else {
        let name = pathname(path)?;
        if name.is_empty() {
            return Err(libc::ENOENT);
        }
        check_dir(dir, name)?;
        path_attr(name)?
    };
    store_stat(out, attr)
}

// Linux AArch64's asm-generic stat ABI differs from the kernel's newlib stat.
#[repr(C)]
struct LinuxStat {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    pad1: u64,
    size: i64,
    blksize: i32,
    pad2: i32,
    blocks: i64,
    atime: [u64; 2],
    mtime: [u64; 2],
    ctime: [u64; 2],
    unused: [u32; 2],
}

const _: () = assert!(core::mem::size_of::<LinuxStat>() == 128);

fn store_stat(out: usize, attr: FileAttr) -> Result<usize> {
    if out == 0 {
        return Err(libc::EFAULT);
    }
    let time = |t: core::time::Duration| [t.as_secs(), u64::from(t.subsec_nanos())];
    let stat = LinuxStat {
        dev: attr.dev as u64,
        ino: attr.ino as u64,
        mode: attr.mode,
        nlink: attr.nlinks,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev as u64,
        pad1: 0,
        size: attr.size as i64,
        blksize: attr.blk_size as i32,
        pad2: 0,
        blocks: (attr.blocks.saturating_mul(attr.blk_size) / 512) as i64,
        atime: time(attr.atime),
        mtime: time(attr.mtime),
        ctime: time(attr.ctime),
        unused: [0; 2],
    };
    // SAFETY: the trusted syscall caller supplies room for the Linux structure.
    unsafe { (out as *mut LinuxStat).write_unaligned(stat) };
    Ok(0)
}

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

fn writev(fd: i32, iovs: *const Iovec, count: usize) -> isize {
    if count > 1024 {
        return -(libc::EINVAL as isize);
    }
    if count == 0 {
        return 0;
    }
    if iovs.is_null() {
        return -(libc::EFAULT as isize);
    }
    let mut written = 0;
    for index in 0..count {
        // SAFETY: a trusted Linux caller supplies count initialized entries.
        let iov = unsafe { iovs.add(index).read_unaligned() };
        let remaining = MAX_RW_COUNT - written;
        let len = iov.len.min(remaining);
        if len == 0 {
            continue;
        }
        let count = syscalls::write(fd, iov.base, len);
        if count < 0 {
            return if written == 0 {
                count
            } else {
                written as isize
            };
        }
        written += count as usize;
        if count as usize != len {
            break;
        }
    }
    written as isize
}

// BlueKernel's VFS uses newlib errno values. Translate only the syscall error
// interval so high-half process addresses returned by mmap and brk pass through.
pub(super) fn linux_return(value: isize) -> usize {
    if !(-4095..0).contains(&value) {
        return value as usize;
    }
    let errno = match (-value) as i32 {
        base @ 1..=34 => base,
        libc::ENAMETOOLONG => 36,
        libc::ENOSYS => super::LINUX_ENOSYS,
        libc::ENOTEMPTY => 39,
        libc::ELOOP => 40,
        libc::ENODATA => 61,
        libc::EOVERFLOW => 75,
        libc::EILSEQ => 84,
        libc::ENOTSUP | libc::EOPNOTSUPP => 95,
        libc::ETIMEDOUT => 110,
        libc::ESTALE => 116,
        _ => 5, // EIO
    };
    -(errno as isize) as usize
}
