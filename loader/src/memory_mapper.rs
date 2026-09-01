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
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage},
    image::{PreparedProtectionPlan, ProtectionCapabilities, ProtectionLevel},
    memory::{
        AllocationOffset, AllocationRequest, ImageAllocation, ImageMemory, ImageProtectionMemory,
        Placement,
    },
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

    pub(crate) const fn without(self, removed: Self) -> Self {
        Self(self.0 & !removed.0)
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

#[derive(Debug)]
pub(crate) enum MappingMode {
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
    pub(crate) fn mapping_mode(&self) -> &MappingMode {
        &self.mode
    }

    pub(crate) fn install_loaded_image(
        &mut self,
        load_bias: TargetAddress,
        runtime_entry: TargetAddress,
    ) -> LoadResult<()> {
        let allocation = *self.allocation()?;
        let virtual_start = allocation.base().checked_sub(load_bias)?;
        let virtual_end = TargetAddress::new(virtual_start).checked_add(allocation.len())?;
        let virtual_entry = runtime_entry.checked_sub(load_bias)?;

        self.virtual_start =
            usize::try_from(virtual_start).map_err(|_| compatibility_install_error(allocation))?;
        self.virtual_end = usize::try_from(virtual_end.get())
            .map_err(|_| compatibility_install_error(allocation))?;
        self.virtual_entry =
            usize::try_from(virtual_entry).map_err(|_| compatibility_install_error(allocation))?;
        Ok(())
    }

    #[inline]
    pub fn entry(&self) -> usize {
        self.virtual_entry
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
        Ok(vaddr - self.virtual_start)
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
}

impl ImageMemory for MemoryMapper {
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<()> {
        match (&self.mode, request.placement()) {
            (MappingMode::Allocated, Placement::Anywhere) => {
                if !self.mem.base().is_null() || self.allocattion.is_some() {
                    return Err(allocation_error(&request));
                }

                let size =
                    usize::try_from(request.size()).map_err(|_| allocation_error(&request))?;
                let align =
                    usize::try_from(request.align()).map_err(|_| allocation_error(&request))?;
                if size == 0 {
                    return Err(allocation_error(&request));
                }
                let layout = Layout::from_size_align(size, align)
                    .map_err(|_| allocation_error(&request))?;

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
                let base = TargetAddress::new(u64::try_from(storage.base() as usize).map_err(
                    |_| allocation_error(&request),
                )?);
                let allocation = ImageAllocation::new(base, request.size(), request.align());
                self.mem = storage;
                self.allocattion = Some(allocation);
                Ok(())
            }
            // A fixed image borrows its span from the mapper's static
            // regions: validate the whole span before recording anything, and
            // never touch the heap storage.
            (MappingMode::Fixed(_), Placement::Fixed(range)) => {
                if self.allocattion.is_some() {
                    return Err(allocation_error(&request));
                }
                let start =
                    usize::try_from(range.start().get()).map_err(|_| allocation_error(&request))?;
                let len =
                    usize::try_from(range.len()).map_err(|_| allocation_error(&request))?;
                self.validate_fixed_span(start, len, MemoryPermissions::NONE)
                    .map_err(|_| allocation_error(&request))?;
                self.allocattion = Some(ImageAllocation::new(
                    range.start(),
                    range.len(),
                    request.align(),
                ));
                Ok(())
            }
            _ => Err(allocation_error(&request)),
        }
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
        match &self.mode {
            MappingMode::Allocated => {
                let base = self.mem.base();
                if base.is_null() || self.mem.size() < end {
                    return Err(memory_access_error(*allocation, offset, len));
                };
                Ok(unsafe { base.add(offset_usize) })
            }
            // Fixed images already validated their span against the static
            // regions at allocation time; the offset bounds check above keeps
            // accesses inside the recorded allocation.
            MappingMode::Fixed(_) => {
                let base = usize::try_from(allocation.base().get())
                    .map_err(|_| memory_access_error(*allocation, offset, len))?;
                Ok((base + offset_usize) as *mut u8)
            }
        }
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

impl ImageProtectionMemory for MemoryMapper {
    fn protect(
        &mut self,
        offset: AllocationOffset,
        len: u64,
        _permissions: MemoryPermissions,
    ) -> LoadResult<ProtectionLevel> {
        self.image_span(offset, len)?;
        Ok(ProtectionLevel::LogicalOnly)
    }

    fn protection_capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities::new(1, usize::MAX)
    }

    fn validate_protection_aliases(
        &self,
        allocation: &ImageAllocation,
        _prepared: &PreparedProtectionPlan,
    ) -> LoadResult<()> {
        let actual = self
            .allocation()
            .map_err(|error| error.at_stage(LoadStage::Seal))?;
        if actual == allocation {
            Ok(())
        } else {
            Err(protection_backend_error(allocation))
        }
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

fn protection_backend_error(allocation: &ImageAllocation) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base: allocation.base(),
            len: allocation.len(),
            align: allocation.align(),
        },
    )
    .at_stage(LoadStage::Seal)
}

fn compatibility_install_error(allocation: ImageAllocation) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base: allocation.base(),
            len: allocation.len(),
            align: allocation.align(),
        },
    )
}
