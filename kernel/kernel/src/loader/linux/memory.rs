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

use crate::vfs::File;
use alloc::vec::Vec;
use blueos_infra::storage::Storage;
use blueos_loader::{
    memory::{AllocationOffset, TargetAddress, TargetRange},
    CodeCache, ImageMapping, MemoryPermissions,
};
use core::{alloc::Layout, ops::Range, slice};

use super::{FlatElf, KernelCodeCache};

pub(crate) const PAGE_SIZE: usize = 4096;
const MAP_PRIVATE: usize = 2;
const MAP_FIXED: usize = 0x10;
pub(crate) const MAP_ANONYMOUS: usize = 0x20;
// Linux accepts this legacy hint from ld.so when mapping DSOs.
const MAP_DENYWRITE: usize = 0x800;
const BRK_RESERVATION: usize = 1024 * 1024;

type Result<T> = core::result::Result<T, i32>;

#[must_use = "the process must retain its ELF and mmap backing through retirement"]
pub(super) struct LinuxMemory {
    images: [FlatElf; 2],
    heap: Storage,
    brk: usize,
    mappings: Vec<Mapping>,
}

#[must_use = "retain the backing while any page in this reservation is mapped"]
struct Mapping {
    storage: Storage,
    // None is an unmapped page. Some(NONE) is a mapped PROT_NONE page.
    pages: Vec<Option<MemoryPermissions>>,
}

impl Mapping {
    fn range(&self) -> Range<usize> {
        let start = self.storage.base().addr();
        start..start + self.storage.size()
    }

    fn page_indices(&self, start: usize, len: usize) -> Range<usize> {
        let first = (start - self.storage.base().addr()) / PAGE_SIZE;
        first..first + len / PAGE_SIZE
    }
}

impl LinuxMemory {
    pub(super) fn new(images: [FlatElf; 2]) -> Result<Self> {
        let heap = allocate(BRK_RESERVATION)?;
        let brk = heap.base().addr();
        Ok(Self {
            images,
            heap,
            brk,
            mappings: Vec::new(),
        })
    }

    pub(super) fn brk(&mut self, end: usize) -> usize {
        let start = self.heap.base().addr();
        if (start..=start + self.heap.size()).contains(&end) {
            if end > self.brk {
                // SAFETY: the checked range lies in the reserved process heap.
                unsafe {
                    self.heap
                        .base()
                        .add(self.brk - start)
                        .write_bytes(0, end - self.brk)
                };
            }
            self.brk = end;
        }
        self.brk
    }

    pub(super) fn mmap(
        &mut self,
        address: usize,
        len: usize,
        prot: usize,
        flags: usize,
        file: Option<(&File, u64)>,
    ) -> Result<usize> {
        let permissions = permissions(prot)?;
        let len = page_len(len)?;
        if flags & !(MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE) != 0
            || flags & MAP_PRIVATE == 0
        {
            return Err(libc::EINVAL);
        }
        if flags & MAP_FIXED != 0 {
            let span = page_range(address, len)?;
            let mapping = self
                .mappings
                .iter_mut()
                .find(|mapping| contains(&mapping.range(), &span))
                .ok_or(libc::ENOMEM)?;
            let offset = address - mapping.storage.base().addr();
            // SAFETY: the reservation owns the checked destination range.
            let dest = unsafe { mapping.storage.base().add(offset) };
            if file.is_some() {
                // Preserve the previous bytes and mapping if file I/O fails.
                let staged = allocate(len)?;
                populate(&staged, file)?;
                // SAFETY: both allocations cover len bytes and are disjoint.
                unsafe { staged.base().copy_to_nonoverlapping(dest, len) };
            } else {
                // SAFETY: the checked destination covers len bytes.
                unsafe { dest.write_bytes(0, len) };
            }
            publish(address, len, permissions)?;
            let pages = mapping.page_indices(address, len);
            mapping.pages[pages].fill(Some(permissions));
            return Ok(address);
        }

        self.mappings.try_reserve(1).map_err(|_| libc::ENOMEM)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(len / PAGE_SIZE)
            .map_err(|_| libc::ENOMEM)?;
        pages.resize(len / PAGE_SIZE, Some(permissions));
        let storage = allocate(len)?;
        populate(&storage, file)?;
        let address = storage.base().addr();
        publish(address, len, permissions)?;
        self.mappings.push(Mapping { storage, pages });
        Ok(address)
    }

    pub(super) fn munmap(&mut self, address: usize, len: usize) -> Result<()> {
        let span = page_range(address, len)?;
        if self
            .images
            .iter()
            .any(|image| overlaps(&image_range(image), &span))
            || overlaps(
                &(self.heap.base().addr()..self.heap.base().addr() + self.heap.size()),
                &span,
            )
        {
            return Err(libc::EINVAL);
        }
        self.mappings.retain_mut(|mapping| {
            let range = mapping.range();
            let start = range.start.max(span.start);
            let end = range.end.min(span.end);
            if start < end {
                let pages = mapping.page_indices(start, end - start);
                mapping.pages[pages].fill(None);
            }
            mapping.pages.iter().any(Option::is_some)
        });
        Ok(())
    }

    pub(super) fn mprotect(&mut self, address: usize, len: usize, prot: usize) -> Result<()> {
        let permissions = permissions(prot)?;
        if len == 0 && address.is_multiple_of(PAGE_SIZE) {
            return Ok(());
        }
        let span = page_range(address, len)?;
        let len = span.len();
        if let Some(image) = self
            .images
            .iter_mut()
            .find(|image| contains(&image_range(image), &span))
        {
            let offset = address - image.allocation().base().get() as usize;
            image
                .allocation_mut()
                .set_permissions(
                    AllocationOffset::new(offset as u64),
                    len as u64,
                    permissions,
                )
                .map_err(|_| libc::ENOMEM)?;
            return publish(address, len, permissions);
        }
        let mapping = self
            .mappings
            .iter_mut()
            .find(|mapping| contains(&mapping.range(), &span))
            .ok_or(libc::ENOMEM)?;
        let pages = mapping.page_indices(address, len);
        if mapping.pages[pages.clone()].iter().any(Option::is_none) {
            return Err(libc::ENOMEM);
        }
        publish(address, len, permissions)?;
        mapping.pages[pages].fill(Some(permissions));
        Ok(())
    }
}

fn allocate(size: usize) -> Result<Storage> {
    let layout = Layout::from_size_align(size, PAGE_SIZE).map_err(|_| libc::ENOMEM)?;
    Storage::try_from_layout(layout).ok_or(libc::ENOMEM)
}

fn populate(storage: &Storage, file: Option<(&File, u64)>) -> Result<()> {
    // SAFETY: the unpublished backing has exclusive access for the entire fill.
    unsafe { storage.base().write_bytes(0, storage.size()) };
    if let Some((file, offset)) = file {
        let file_len = file.file_len().map_err(|err| -err.to_errno())?;
        let available = file_len.saturating_sub(offset).min(storage.size() as u64) as usize;
        // SAFETY: this prefix has been initialized and is exclusively writable.
        let dst = unsafe { slice::from_raw_parts_mut(storage.base(), available) };
        file.read_exact_at(offset, dst)
            .map_err(|err| -err.to_errno())?;
    }
    Ok(())
}

fn permissions(prot: usize) -> Result<MemoryPermissions> {
    if prot & !7 != 0 {
        return Err(libc::EINVAL);
    }
    let mut result = MemoryPermissions::NONE;
    for (flag, permission) in [
        (1, MemoryPermissions::READ),
        (2, MemoryPermissions::WRITE),
        (4, MemoryPermissions::EXECUTE),
    ] {
        if prot & flag != 0 {
            result = result.bitor(permission);
        }
    }
    Ok(result)
}

fn publish(address: usize, len: usize, permissions: MemoryPermissions) -> Result<()> {
    if permissions.contains(MemoryPermissions::EXECUTE) {
        KernelCodeCache::new()
            .synchronize(TargetRange::new(
                TargetAddress::new(address as u64),
                len as u64,
            ))
            .map_err(|_| libc::EINVAL)?;
    }
    Ok(())
}

fn page_len(len: usize) -> Result<usize> {
    if len == 0 {
        return Err(libc::EINVAL);
    }
    len.checked_next_multiple_of(PAGE_SIZE).ok_or(libc::EINVAL)
}

fn page_range(start: usize, len: usize) -> Result<Range<usize>> {
    if !start.is_multiple_of(PAGE_SIZE) {
        return Err(libc::EINVAL);
    }
    let end = start.checked_add(page_len(len)?).ok_or(libc::EINVAL)?;
    Ok(start..end)
}

fn image_range(image: &FlatElf) -> Range<usize> {
    let start = image.allocation().base().get() as usize;
    start..start + image.allocation().len() as usize
}

fn contains(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}
