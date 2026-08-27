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

use blueos_infra::storage::Storage;
use core::alloc::Layout;

use crate::{
    AllocationId, AllocationLease, AllocationOwnership, AllocationRequest, ErrorContext,
    ExpectedElfType, ImageAllocation, ImageCommitMemory, ImageMemory, ImageProtectionMemory,
    LoadError, LoadErrorKind, LoadResult, LoadStage, MutationProgress, Placement,
    ProtectionCapabilities, SealedState, TargetAddr, TargetLocation,
};

const IMAGE_ALLOCATION_ID: AllocationId = AllocationId::new(0);

type MapperResult<T> = core::result::Result<T, &'static str>;

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

    pub const fn without(self, removed: Self) -> Self {
        Self(self.0 & !removed.0)
    }

    pub const fn contains(self, requested: Self) -> bool {
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
enum MappingMode {
    Allocated,
    Fixed(&'static [MemoryRegion]),
}

#[derive(Debug)]
pub struct MemoryMapper {
    sealed_entry: Option<usize>,
    mem: Storage,
    mode: MappingMode,
    image_allocation: Option<ImageAllocation>,
    installed_lease: Option<AllocationLease>,
    fixed_poisoned: bool,
}

#[derive(Debug)]
pub struct PreparedMapperInstall {
    allocation: ImageAllocation,
    entry: usize,
}

impl MemoryMapper {
    #[inline]
    pub fn new(regions: Option<&'static [MemoryRegion]>) -> Self {
        Self {
            sealed_entry: None,
            mem: Storage::default(),
            mode: match regions {
                Some(regions) => MappingMode::Fixed(regions),
                None => MappingMode::Allocated,
            },
            image_allocation: None,
            installed_lease: None,
            fixed_poisoned: false,
        }
    }

    #[inline]
    pub(crate) fn expected_elf_type(&self) -> ExpectedElfType {
        match &self.mode {
            MappingMode::Allocated => ExpectedElfType::Dyn,
            MappingMode::Fixed(_) => ExpectedElfType::Exec,
        }
    }

    #[inline]
    pub fn real_start(&self) -> MapperResult<usize> {
        let base = self.mem.base();
        if base.is_null() {
            return Err("Memory not allocated yet");
        }
        Ok(base as usize)
    }

    #[inline]
    pub fn real_entry(&self) -> MapperResult<usize> {
        self.sealed_entry.ok_or("Image has not been sealed")
    }

    #[inline]
    pub const fn is_fixed_poisoned(&self) -> bool {
        self.fixed_poisoned
    }

    /// Clear the fixed-image poison marker after the platform has restored the
    /// complete authorized range to a known state.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that no stale entry can execute and that every
    /// byte and protection attribute potentially modified by the failed load has
    /// been restored before calling this method.
    pub unsafe fn reset_fixed_poison(&mut self) {
        self.fixed_poisoned = false;
    }

    fn prepare_sealed_install(
        &self,
        allocation: &ImageAllocation,
        sealed: &SealedState,
    ) -> LoadResult<PreparedMapperInstall> {
        let active = self
            .image_allocation
            .filter(|active| active == allocation && active == sealed.allocation())
            .filter(|_| self.installed_lease.is_none() && self.sealed_entry.is_none())
            .ok_or_else(|| sealed_install_error(sealed))?;
        let entry =
            usize::try_from(sealed.entry().get()).map_err(|_| sealed_install_error(sealed))?;
        let entry_in_allocation = sealed
            .entry()
            .get()
            .checked_sub(active.target_base().get())
            .is_some_and(|offset| offset < active.len());
        if !entry_in_allocation {
            return Err(sealed_install_error(sealed));
        }
        if matches!(self.mode, MappingMode::Fixed(_)) {
            self.validate_fixed_span(entry, 1, MemoryPermissions::EXECUTE)
                .map_err(|_| sealed_install_error(sealed))?;
        }
        Ok(PreparedMapperInstall {
            allocation: active,
            entry,
        })
    }

    pub(crate) fn validate_fixed_span(
        &self,
        start: usize,
        size: usize,
        requested: MemoryPermissions,
    ) -> MapperResult<()> {
        let MappingMode::Fixed(regions) = &self.mode else {
            return Err("Fixed span requires a fixed mapper");
        };
        let valid = regions.iter().any(|region| {
            region.start < region.end
                && start >= region.start
                && start.checked_add(size).is_some_and(|end| end <= region.end)
                && region.permissions.contains(requested)
        });
        if valid {
            Ok(())
        } else {
            Err("Address span is outside authorized regions")
        }
    }
}

impl ImageMemory for MemoryMapper {
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<AllocationLease> {
        if self.image_allocation.is_some()
            || self.installed_lease.is_some()
            || (matches!(self.mode, MappingMode::Fixed(_)) && self.fixed_poisoned)
        {
            return Err(allocation_error(request));
        }
        let size = usize::try_from(request.size()).map_err(|_| allocation_error(request))?;
        let align = usize::try_from(request.align()).map_err(|_| allocation_error(request))?;

        match (&self.mode, request.placement()) {
            (MappingMode::Allocated, Placement::Anywhere) => {
                if !self.mem.base().is_null() {
                    return Err(allocation_error(request));
                }
                let layout = Layout::from_size_align(size, align).map_err(|_| {
                    LoadError::new(
                        LoadStage::Allocate,
                        LoadErrorKind::InvalidAlignment,
                        ErrorContext::Allocation {
                            base: TargetAddr::new(0),
                            len: request.size(),
                            align: request.align(),
                        },
                    )
                })?;
                let storage = Storage::try_from_layout(layout).ok_or_else(|| {
                    LoadError::new(
                        LoadStage::Allocate,
                        LoadErrorKind::OutOfMemory,
                        ErrorContext::Allocation {
                            base: TargetAddr::new(0),
                            len: request.size(),
                            align: request.align(),
                        },
                    )
                })?;
                let target_base = TargetAddr::new(
                    u64::try_from(storage.base() as usize)
                        .map_err(|_| allocation_error(request))?,
                );
                self.mem = storage;
                let allocation = ImageAllocation::new(
                    IMAGE_ALLOCATION_ID,
                    target_base,
                    request.size(),
                    request.align(),
                    AllocationOwnership::Owned,
                );
                self.image_allocation = Some(allocation);
                // SAFETY: this mapper just created the allocation and keeps no
                // second lease for it.
                Ok(unsafe { AllocationLease::from_allocation(allocation) })
            }
            (MappingMode::Fixed(_), Placement::Fixed(range)) => {
                let start =
                    usize::try_from(range.start().get()).map_err(|_| allocation_error(request))?;
                let len = usize::try_from(range.len()).map_err(|_| allocation_error(request))?;
                self.validate_fixed_span(start, len, MemoryPermissions::NONE)
                    .map_err(|_| allocation_error(request))?;
                let allocation = ImageAllocation::new(
                    IMAGE_ALLOCATION_ID,
                    range.start(),
                    range.len(),
                    request.align(),
                    AllocationOwnership::BorrowedFixed,
                );
                self.image_allocation = Some(allocation);
                // SAFETY: this mapper has exclusively reserved the authorized
                // fixed span and keeps no second lease for it.
                Ok(unsafe { AllocationLease::from_allocation(allocation) })
            }
            _ => Err(allocation_error(request)),
        }
    }

    fn abort_image(&mut self, lease: AllocationLease, progress: MutationProgress) {
        let allocation = *lease.allocation();
        if self.image_allocation != Some(allocation) {
            return;
        }
        if allocation.ownership() == AllocationOwnership::Owned {
            self.mem = Storage::default();
        } else if progress >= MutationProgress::BytesModified {
            self.fixed_poisoned = true;
        }
        self.sealed_entry = None;
        self.image_allocation = None;
    }

    fn release_committed(&mut self, lease: AllocationLease) {
        let allocation = *lease.allocation();
        if self.image_allocation != Some(allocation) {
            return;
        }
        if allocation.ownership() == AllocationOwnership::Owned {
            self.mem = Storage::default();
        }
        self.sealed_entry = None;
        self.image_allocation = None;
    }

    fn validate_access(
        &self,
        location: TargetLocation,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<()> {
        self.image_span(location, len, permissions).map(|_| ())
    }

    fn write(&mut self, location: TargetLocation, data: &[u8]) -> LoadResult<()> {
        let len = u64::try_from(data.len()).map_err(|_| memory_access_error(location, u64::MAX))?;
        let target = self.image_span(location, len, MemoryPermissions::WRITE)?;
        if data.is_empty() {
            return Ok(());
        }
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len()) };
        Ok(())
    }

    fn zero(&mut self, location: TargetLocation, len: u64) -> LoadResult<()> {
        let target = self.image_span(location, len, MemoryPermissions::WRITE)?;
        let len = usize::try_from(len).map_err(|_| memory_access_error(location, len))?;
        if len != 0 {
            unsafe { core::ptr::write_bytes(target, 0, len) };
        }
        Ok(())
    }

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> LoadResult<()> {
        let len = u64::try_from(dst.len()).map_err(|_| memory_access_error(location, u64::MAX))?;
        let source = self.image_span(location, len, MemoryPermissions::READ)?;
        if !dst.is_empty() {
            unsafe { core::ptr::copy_nonoverlapping(source, dst.as_mut_ptr(), dst.len()) };
        }
        Ok(())
    }

    fn protect(
        &mut self,
        location: TargetLocation,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<crate::ProtectionLevel> {
        self.validate_access(location, len, permissions)?;
        Ok(crate::ProtectionLevel::LogicalOnly)
    }
}

impl ImageCommitMemory for MemoryMapper {
    type PreparedInstall = PreparedMapperInstall;
    type CommitReceipt = ();

    fn prepare_install(
        &mut self,
        allocation: &ImageAllocation,
        sealed: &SealedState,
    ) -> LoadResult<Self::PreparedInstall> {
        self.prepare_sealed_install(allocation, sealed)
    }

    unsafe fn commit_install(
        &mut self,
        prepared: Self::PreparedInstall,
        sealed: SealedState,
        lease: AllocationLease,
    ) -> Self::CommitReceipt {
        let _ = sealed;
        self.image_allocation = Some(prepared.allocation);
        self.sealed_entry = Some(prepared.entry);
        self.installed_lease = Some(lease);
    }
}

impl ImageProtectionMemory for MemoryMapper {
    fn protection_capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities::new(1, usize::MAX)
    }

    fn validate_protection_aliases(
        &self,
        _allocation: &ImageAllocation,
        _prepared: &crate::PreparedProtectionPlan,
    ) -> LoadResult<()> {
        // MemoryMapper is a compatibility adapter with no hardware permission
        // enforcement. `protect()` therefore reports `LogicalOnly` for every
        // range instead of claiming that writable aliases were removed.
        Ok(())
    }
}

impl MemoryMapper {
    fn image_span(
        &self,
        location: TargetLocation,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<*mut u8> {
        let allocation = self
            .image_allocation
            .filter(|allocation| allocation.id() == location.allocation())
            .ok_or_else(|| memory_access_error(location, len))?;
        let end = location
            .offset()
            .checked_add(len)
            .filter(|end| *end <= allocation.len())
            .ok_or_else(|| memory_access_error(location, len))?;
        let offset =
            usize::try_from(location.offset()).map_err(|_| memory_access_error(location, len))?;
        let end_usize = usize::try_from(end).map_err(|_| memory_access_error(location, len))?;

        match &self.mode {
            MappingMode::Allocated => {
                let base = self.mem.base();
                if base.is_null() || self.mem.size() < end_usize {
                    return Err(memory_access_error(location, len));
                }
                Ok(unsafe { base.add(offset) })
            }
            MappingMode::Fixed(_) => {
                let start = allocation
                    .target_base()
                    .get()
                    .checked_add(location.offset())
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| memory_access_error(location, len))?;
                let len_usize =
                    usize::try_from(len).map_err(|_| memory_access_error(location, len))?;
                self.validate_fixed_span(start, len_usize, permissions)
                    .map_err(|_| memory_access_error(location, len))?;
                Ok(start as *mut u8)
            }
        }
    }
}

fn allocation_error(request: &AllocationRequest) -> LoadError {
    let base = match request.placement() {
        Placement::Anywhere => TargetAddr::new(0),
        Placement::Fixed(range) => range.start(),
    };
    LoadError::new(
        LoadStage::Allocate,
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base,
            len: request.size(),
            align: request.align(),
        },
    )
}

fn memory_access_error(location: TargetLocation, len: u64) -> LoadError {
    LoadError::new(
        LoadStage::Map,
        LoadErrorKind::Backend,
        ErrorContext::MemoryAccess {
            allocation: location.allocation(),
            offset: location.offset(),
            len,
        },
    )
}

fn sealed_install_error(sealed: &SealedState) -> LoadError {
    LoadError::new(
        LoadStage::Seal,
        LoadErrorKind::Backend,
        ErrorContext::TargetRange {
            start: sealed.entry(),
            len: 1,
        },
    )
}
