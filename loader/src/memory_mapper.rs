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

use alloc::vec::Vec;
use blueos_infra::storage::Storage;
use core::alloc::Layout;

use crate::{
    address::TargetAddress,
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult},
    memory::{AllocationOffset, AllocationRequest, ImageAllocation, ImageMemory},
};

pub type Result<T> = core::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPermissions(u8);

impl MemoryPermissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }

    pub(crate) const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    start: usize,
    end: usize,
    permissions: MemoryPermissions,
}

impl MemoryRegion {
    /// Authorizes a fixed address range for accesses described by `permissions`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `[start, end)` is a valid mapped range for every
    /// advertised permission and remains so for the lifetime of any mapper that uses
    /// this region. While a mapper accesses the range, it must not alias Rust references
    /// or receive conflicting accesses.
    pub const unsafe fn new(start: usize, end: usize, permissions: MemoryPermissions) -> Self {
        Self {
            start,
            end,
            permissions,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappingModeKind {
    Allocated,
    Fixed,
}

#[derive(Debug)]
enum MappingMode {
    Allocated,
    Fixed(&'static [MemoryRegion]),
}

#[derive(Debug)]
pub struct MemoryMapper {
    virtual_entry: usize,
    virtual_start: usize,
    virtual_end: usize,
    mem: Storage,
    mode: MappingMode,
    allocattion: Option<ImageAllocation>,
}

impl MemoryMapper {
    #[inline]
    pub fn new(regions: Option<&'static [MemoryRegion]>) -> Self {
        Self {
            virtual_entry: 0,
            virtual_start: usize::MAX,
            virtual_end: 0,
            mem: Storage::default(),
            mode: match regions {
                Some(regions) => MappingMode::Fixed(regions),
                None => MappingMode::Allocated,
            },
            allocattion: None,
        }
    }

    #[inline]
    pub(crate) fn mode_kind(&self) -> MappingModeKind {
        match &self.mode {
            MappingMode::Allocated => MappingModeKind::Allocated,
            MappingMode::Fixed(_) => MappingModeKind::Fixed,
        }
    }

    #[inline]
    pub fn entry(&self) -> usize {
        self.virtual_entry
    }

    #[inline]
    pub fn set_entry(&mut self, entry: usize) -> &mut Self {
        self.virtual_entry = entry;
        self
    }

    #[inline]
    pub fn start(&self) -> usize {
        self.virtual_start
    }

    #[inline]
    pub fn update_start(&mut self, val: usize) -> &mut Self {
        self.virtual_start = core::cmp::min(self.virtual_start, val);
        self
    }

    #[inline]
    pub fn update_end(&mut self, val: usize) -> &mut Self {
        self.virtual_end = core::cmp::max(self.virtual_end, val);
        self
    }

    #[inline]
    pub fn total_size(&self) -> Result<usize> {
        if self.virtual_end < self.virtual_start {
            return Err("Illegal memory size");
        }
        Ok(self.virtual_end - self.virtual_start)
    }

    #[inline]
    pub fn allocate_memory(&mut self) -> Result<usize> {
        // FIXME: We are not using paging yet, so alignment(usually
        // 4096) specified in program header is not applied here.
        // BlueKernel on AArch64 uses MMU by default, which requires aligning to
        // a page boundary.
        #[cfg(any(target_arch = "aarch64"))]
        const ALIGN: usize = 4096;
        #[cfg(not(any(target_arch = "aarch64")))]
        const ALIGN: usize = 2 * core::mem::size_of::<usize>();
        let Ok(layout) = Layout::from_size_align(self.total_size()?, ALIGN) else {
            return Err("Illegal memory layout");
        };
        self.mem = Storage::from_layout(layout);
        Ok(self.mem.size())
    }

    #[inline]
    pub fn real_start(&self) -> Result<usize> {
        let base = self.mem.base();
        if base.is_null() {
            return Err("Memory not allocated yet");
        }
        Ok(base as usize)
    }

    #[inline]
    pub fn real_entry(&self) -> Result<usize> {
        match &self.mode {
            MappingMode::Allocated => Ok(self.inner_real_ptr(self.virtual_entry)? as usize),
            MappingMode::Fixed(_) => {
                self.validate_fixed_span(self.virtual_entry, 1, MemoryPermissions::EXECUTE)?;
                Ok(self.virtual_entry)
            }
        }
    }

    pub(crate) fn validate_fixed_span(
        &self,
        start: usize,
        size: usize,
        requested: MemoryPermissions,
    ) -> Result<()> {
        let MappingMode::Fixed(regions) = &self.mode else {
            return Err("Fixed span requires a fixed mapper");
        };
        let valid = regions.iter().any(|region| {
            region.start < region.end
                && start >= region.start
                && start + size <= region.end
                && region.permissions.contains(requested)
        });
        if valid {
            Ok(())
        } else {
            Err("Address span is outside authorized regions")
        }
    }

    fn inner_real_offset(&self, vaddr: usize) -> Result<usize> {
        if vaddr < self.virtual_start || vaddr >= self.virtual_end {
            return Err("The virtual address is in an illegal memory region");
        }
        let total_size = self.total_size()?;
        let offset = vaddr - self.virtual_start;
        if offset >= total_size {
            return Err("The offset is beyond the virtual memory region");
        }
        Ok(offset)
    }

    fn inner_real_ptr(&self, vaddr: usize) -> Result<*mut u8> {
        match &self.mode {
            MappingMode::Allocated => {
                let offset = self.inner_real_offset(vaddr)?;
                if offset >= self.mem.size() {
                    return Err("The offset is beyond the allocated memory region");
                }
                let base = self.mem.base();
                if base.is_null() {
                    return Err("Memory not allocated yet");
                }
                Ok(unsafe { base.add(offset) })
            }
            MappingMode::Fixed(_) => {
                self.validate_fixed_span(vaddr, 1, MemoryPermissions::NONE)?;
                Ok(vaddr as *mut u8)
            }
        }
    }

    fn inner_real_begin(&self, vaddr: usize, size: usize) -> Result<*mut u8> {
        match &self.mode {
            MappingMode::Allocated => {
                if vaddr < self.virtual_start || vaddr + size > self.virtual_end {
                    return Err("The span of the data is in an illegal memory region");
                }
                let real_begin = self.inner_real_ptr(vaddr)?;
                let _real_end = core::hint::black_box(self.inner_real_ptr(vaddr + size - 1)?);
                Ok(real_begin)
            }
            MappingMode::Fixed(_) => {
                self.validate_fixed_span(vaddr, size, MemoryPermissions::NONE)?;
                Ok(vaddr as *mut u8)
            }
        }
    }

    pub fn write_slice_at(&mut self, vaddr: usize, data: &[u8]) -> Result<usize> {
        let size = data.len();
        if size == 0 {
            return Ok(size);
        }
        let real_begin = self.inner_real_begin(vaddr, size)?;
        // FIXME: Is it safe enough to use copy_nonoverlapping?
        unsafe { core::ptr::copy(data.as_ptr(), real_begin, data.len()) };
        Ok(size)
    }

    pub fn write_value_at<T>(&mut self, vaddr: usize, val: T) -> Result<usize>
    where
        T: Sized,
    {
        let size = core::mem::size_of::<T>();
        let real_begin = self.inner_real_begin(vaddr, size)?;
        let val_ptr: *mut T = unsafe { core::mem::transmute(real_begin) };
        unsafe { val_ptr.write(val) };
        Ok(size)
    }
}

impl ImageMemory for MemoryMapper {
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<()> {
        if !matches!(self.mode, MappingMode::Allocated)
            || !self.mem.base().is_null()
            || self.allocattion.is_some()
        {
            return Err(allocation_error(&request));
        }

        let size = usize::try_from(request.size()).map_err(|_| allocation_error(&request))?;
        let align = usize::try_from(request.align()).map_err(|_| allocation_error(&request))?;
        if size == 0 {
            return Err(allocation_error(&request));
        }
        let layout =
            Layout::from_size_align(size, align).map_err(|_| allocation_error(&request))?;

        let storage = Storage::try_from_layout(layout).ok_or_else(|| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::Allocation {
                    base: TargetAddress::new(0),
                    len: request.size(),
                    align: request.align(),
                },
            )
        })?;
        let base = TargetAddress::new(
            u64::try_from(storage.base() as usize).map_err(|_| allocation_error(&request))?,
        );
        let allocation = ImageAllocation::new(base, request.size(), request.align());
        self.allocattion = Some(allocation);
        Ok(())
    }

    fn allocation(&self) -> LoadResult<&ImageAllocation> {
        if let Some(allocation) = &self.allocattion {
            return Ok(allocation);
        }
        Err(LoadError::new(
            LoadErrorKind::NotAllocated,
            ErrorContext::Allocation {
                base: TargetAddress::new(0),
                len: 0,
                align: 0,
            },
        ))
    }

    fn image_span(&self, offset: AllocationOffset, len: u64) -> LoadResult<*mut u8> {
        let allocation = self.allocation()?;
        let end = offset
            .value()
            .checked_add(len)
            .filter(|end| *end <= allocation.len())
            .ok_or_else(|| memory_access_error(*allocation, offset, len))?;
        let offset_usize = usize::try_from(offset.value())
            .map_err(|_| memory_access_error(*allocation, offset, len))?;
        let end =
            usize::try_from(end).map_err(|_| memory_access_error(*allocation, offset, len))?;
        let base = self.mem.base();
        if base.is_null() || self.mem.size() < end {
            return Err(memory_access_error(*allocation, offset, len));
        };
        Ok(unsafe { base.add(offset_usize) })
    }

    fn read(&self, offset: AllocationOffset, dst: &mut [u8]) -> LoadResult<()> {
        let allocation = self.allocation()?;
        let len = u64::try_from(dst.len())
            .map_err(|_| memory_access_error(*allocation, offset, u64::MAX))?;
        let source = self.image_span(offset, len)?;
        if !dst.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(source, dst.as_mut_ptr(), dst.len());
            }
        }
        Ok(())
    }

    fn write(&mut self, offset: AllocationOffset, data: &[u8]) -> LoadResult<()> {
        let allocation = self.allocation()?;
        let len = u64::try_from(data.len())
            .map_err(|_| memory_access_error(*allocation, offset, u64::MAX))?;
        let target = self.image_span(offset, len)?;
        if !data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
            }
        }
        Ok(())
    }

    fn zero(&mut self, offset: AllocationOffset, len: u64) -> LoadResult<()> {
        let allocation = self.allocation()?;
        let target = self.image_span(offset, len)?;
        let len =
            usize::try_from(len).map_err(|_| memory_access_error(*allocation, offset, len))?;
        if len != 0 {
            unsafe {
                core::ptr::write_bytes(target, 0, len);
            }
        }
        Ok(())
    }
}

fn allocation_error(request: &AllocationRequest) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base: TargetAddress::new(0),
            len: request.size(),
            align: request.align(),
        },
    )
}

fn memory_access_error(
    allocation: ImageAllocation,
    offset: AllocationOffset,
    len: u64,
) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::MemoryAccess {
            allocation_base: allocation.base(),
            allocation_len: allocation.len(),
            allocation_align: allocation.align(),
            offset: offset.value(),
            len,
        },
    )
}
