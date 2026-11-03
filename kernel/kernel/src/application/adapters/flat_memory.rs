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

//! Shared-flat memory backend for dynamic image loading.
//!
//! [`FlatImageMemory`] is not a per-session backing owner. It is a lightweight
//! handle onto one shared service whose allocation table records every live
//! image allocation. Each link session holds an independent handle (a clone of
//! the same `Arc`) and synchronizes the table only for the duration of a single
//! `ImageMemory` call, never across the whole VFS/link. A reaper reaches the
//! same service through its own handle to release a committed lease exactly
//! once. There is no "current allocation" side channel: every access names the
//! allocation it targets and is validated against the full descriptor.

use alloc::{sync::Arc, vec::Vec};
use core::{
    alloc::Layout,
    sync::atomic::{AtomicU32, Ordering},
};

use blueos_infra::storage::Storage;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    memory::{
        AllocationId, AllocationLease, AllocationOffset, AllocationOwnership, AllocationRequest,
        ImageAllocation, ImageMemory, ImageProtectionMemory, MemoryPermissions, MutationProgress,
        Placement, PreparedProtectionPlan, ProtectionCapabilities, ProtectionLevel, TargetAddress,
    },
    LoadError, LoadResult,
};
use spin::Mutex;

static LAST_SERVICE_NONCE: AtomicU32 = AtomicU32::new(0);

/// Reserve a service namespace once, without reusing it after service drop.
fn reserve_service_nonce(last: &AtomicU32) -> Option<u32> {
    let previous = last
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |nonce| {
            nonce.checked_add(1)
        })
        .ok()?;
    // A successful update proves that this increment cannot overflow.
    Some(previous + 1)
}

/// One live allocation: the stable, non-moving backing storage and the full
/// descriptor it was minted with. `Storage` owns the heap block and frees it on
/// drop, so removing an entry is exactly the release of that image's bytes.
struct FlatAllocationEntry {
    storage: Storage,
    allocation: ImageAllocation,
}

/// Shared allocation table plus the identity nonce and monotonic id counter.
///
/// `nonce` occupies the high 32 bits of every [`AllocationId`]. It is reserved
/// once per service and never reused, including after the service is dropped.
/// `None` means the service namespace is exhausted and allocations must fail.
/// `last_counter` occupies the low 32 bits and never wraps within a service.
#[must_use = "keep the allocation table alive while image resources exist"]
struct FlatMemoryService {
    nonce: Option<u32>,
    entries: Vec<Arc<FlatAllocationEntry>>,
    last_counter: u32,
}

impl FlatMemoryService {
    fn new() -> Self {
        Self {
            nonce: reserve_service_nonce(&LAST_SERVICE_NONCE),
            entries: Vec::new(),
            last_counter: 0,
        }
    }

    /// Mint a unique allocation id from disjoint 32-bit fields. Exhausting
    /// either field fails permanently instead of reissuing an earlier id.
    fn mint_id(&mut self) -> LoadResult<AllocationId> {
        let nonce = self.nonce.ok_or_else(|| allocation_error_u64(0, 0))?;
        let counter = self
            .last_counter
            .checked_add(1)
            .ok_or_else(|| allocation_error_u64(0, 0))?;
        self.last_counter = counter;
        Ok(AllocationId::new(
            (u64::from(nonce) << 32) | u64::from(counter),
        ))
    }

    fn entry(&self, allocation: &ImageAllocation) -> Option<&FlatAllocationEntry> {
        self.entries
            .iter()
            .find(|entry| entry.allocation == *allocation)
            .map(Arc::as_ref)
    }

    fn entry_index(&self, allocation: &ImageAllocation) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.allocation == *allocation)
    }
}

/// A cloneable handle onto the shared-flat memory service.
#[must_use = "keep the allocation service alive while image resources exist"]
pub struct FlatImageMemory {
    service: Arc<Mutex<FlatMemoryService>>,
}

impl FlatImageMemory {
    /// Create a new shared service and return its first handle.
    ///
    /// The boot path creates exactly one service and keeps a handle alive for
    /// the lifetime of the system so it outlives every committed lease; the
    /// reaper obtains its own `Clone` to release those leases.
    /// If service namespaces are exhausted, this handle rejects allocations.
    pub fn new() -> Self {
        Self {
            service: Arc::new(Mutex::new(FlatMemoryService::new())),
        }
    }
}

#[must_use = "keep the pin while a descriptor may access its backing"]
#[derive(Clone)]
pub(crate) struct FlatBackingPin(Arc<FlatAllocationEntry>);

impl FlatImageMemory {
    pub(crate) fn pin(&self, allocation: &ImageAllocation) -> LoadResult<FlatBackingPin> {
        let service = self.service.lock();
        let entry = service
            .entries
            .iter()
            .find(|entry| entry.allocation == *allocation)
            .ok_or_else(|| not_allocated_error(*allocation))?;
        Ok(FlatBackingPin(entry.clone()))
    }
}

impl Default for FlatImageMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FlatImageMemory {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

impl FlatImageMemory {
    /// Consume the unique lease and remove its exact descriptor. Removing
    /// the table's Arc releases the bytes after any physical pins are gone.
    fn remove_allocation(&mut self, allocation: AllocationLease) {
        let mut service = self.service.lock();
        if let Some(index) = service.entry_index(allocation.allocation()) {
            service.entries.swap_remove(index);
        }
    }

    fn image_span(
        service: &FlatMemoryService,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
    ) -> LoadResult<*mut u8> {
        let entry = service
            .entry(allocation)
            .ok_or_else(|| not_allocated_error(*allocation))?;
        let end = offset
            .value()
            .checked_add(len)
            .filter(|end| *end <= allocation.len())
            .ok_or_else(|| memory_access_error(*allocation, offset, len))?;
        let offset_usize = usize::try_from(offset.value())
            .map_err(|_| memory_access_error(*allocation, offset, len))?;
        let end_usize =
            usize::try_from(end).map_err(|_| memory_access_error(*allocation, offset, len))?;
        let base = entry.storage.base();
        if base.is_null() || entry.storage.size() < end_usize {
            return Err(memory_access_error(*allocation, offset, len));
        }
        // SAFETY: checked offset+len stays in this live Storage allocation;
        // offset may be one-past only for an empty access. The caller retains
        // the service lock until any returned pointer has finished being used.
        Ok(unsafe { base.add(offset_usize) })
    }
}

impl ImageMemory for FlatImageMemory {
    fn execution_domain(&self) -> blueos_loader::ExecutionDomainId {
        blueos_loader::ExecutionDomainId::FLAT
    }
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<AllocationLease> {
        // Dynamic images are movable ET_DYN objects loaded from the
        // shared heap. A fixed placement cannot be honoured against this heap
        // backing and is rejected rather than silently redirected.
        if request.placement() != Placement::Anywhere {
            return Err(allocation_error(&request));
        }
        let size = usize::try_from(request.size()).map_err(|_| allocation_error(&request))?;
        let align = usize::try_from(request.align()).map_err(|_| allocation_error(&request))?;
        if size == 0 {
            return Err(allocation_error(&request));
        }
        let layout =
            Layout::from_size_align(size, align).map_err(|_| allocation_error(&request))?;

        let mut service = self.service.lock();
        // Reserve before allocating so the infallible push below cannot fail
        // after we have taken ownership of a heap block.
        service.entries.try_reserve(1).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::Allocation {
                    base: TargetAddress::new(0),
                    len: request.size(),
                    align: request.align(),
                },
            )
        })?;
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
        let allocation = ImageAllocation::with_identity(
            service.mint_id()?,
            base,
            request.size(),
            request.align(),
            AllocationOwnership::Owned,
        );
        service.entries.push(Arc::new(FlatAllocationEntry {
            storage,
            allocation,
        }));
        // SAFETY: the backend just recorded `allocation` in the shared table
        // and mints no other lease for it; the caller receives the sole
        // authority to abort, commit, or release this allocation.
        Ok(unsafe { AllocationLease::new(allocation) })
    }

    fn abort_image(&mut self, allocation: AllocationLease, _progress: MutationProgress) {
        self.remove_allocation(allocation);
    }

    fn release_committed(&mut self, allocation: AllocationLease) {
        self.remove_allocation(allocation);
    }

    fn validate_range(
        &self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
    ) -> LoadResult<()> {
        let service = self.service.lock();
        Self::image_span(&service, allocation, offset, len).map(|_| ())
    }

    fn write(
        &mut self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        data: &[u8],
    ) -> LoadResult<()> {
        let len = u64::try_from(data.len())
            .map_err(|_| memory_access_error(*allocation, offset, u64::MAX))?;
        let service = self.service.lock();
        let target = Self::image_span(&service, allocation, offset, len)?;
        if !data.is_empty() {
            // SAFETY: the lock keeps the validated backing live and excludes
            // concurrent accesses. The input slice is readable for its length
            // and does not alias the backend's private allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
            }
        }
        Ok(())
    }

    fn zero(
        &mut self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
    ) -> LoadResult<()> {
        let service = self.service.lock();
        let target = Self::image_span(&service, allocation, offset, len)?;
        let len =
            usize::try_from(len).map_err(|_| memory_access_error(*allocation, offset, len))?;
        if len != 0 {
            // SAFETY: image_span validated this byte range, and the held
            // service lock prevents release or competing writes until done.
            unsafe {
                core::ptr::write_bytes(target, 0, len);
            }
        }
        Ok(())
    }

    fn read(
        &self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        dst: &mut [u8],
    ) -> LoadResult<()> {
        let len = u64::try_from(dst.len())
            .map_err(|_| memory_access_error(*allocation, offset, u64::MAX))?;
        let service = self.service.lock();
        let source = Self::image_span(&service, allocation, offset, len)?;
        if !dst.is_empty() {
            // SAFETY: the locked table retains readable backing for len bytes;
            // dst is an exclusive, disjoint output slice of the same length.
            unsafe {
                core::ptr::copy_nonoverlapping(source, dst.as_mut_ptr(), dst.len());
            }
        }
        Ok(())
    }
}

impl ImageProtectionMemory for FlatImageMemory {
    fn protect(
        &mut self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
        _permissions: MemoryPermissions,
    ) -> LoadResult<ProtectionLevel> {
        // The shared flat address space has no per-image hardware protection;
        // protection is a logical record only.
        let service = self.service.lock();
        Self::image_span(&service, allocation, offset, len)?;
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
        let service = self.service.lock();
        if service.entry(allocation).is_some() {
            Ok(())
        } else {
            Err(protection_backend_error(allocation))
        }
    }
}

fn allocation_error(request: &AllocationRequest) -> LoadError {
    allocation_error_u64(request.size(), request.align())
}

fn allocation_error_u64(len: u64, align: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Allocation {
            base: TargetAddress::new(0),
            len,
            align,
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

fn not_allocated_error(allocation: ImageAllocation) -> LoadError {
    LoadError::new(
        LoadErrorKind::NotAllocated,
        ErrorContext::Allocation {
            base: allocation.base(),
            len: allocation.len(),
            align: allocation.align(),
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
}

#[cfg(test)]
mod id_tests {
    use super::*;
    use blueos_test_macro::test;

    #[test]
    fn allocation_counter_stops_at_the_low_32_bit_boundary() {
        let mut service = FlatMemoryService::new();
        service.nonce = Some(8);
        service.last_counter = u32::MAX - 1;
        let last = service.mint_id().expect("last counter is still valid");
        assert_eq!(last.value(), (8u64 << 32) | u64::from(u32::MAX));
        for _ in 0..2 {
            assert!(service.mint_id().is_err());
            assert_eq!(service.last_counter, u32::MAX);
        }
    }

    #[test]
    fn counter_exhaustion_does_not_publish_an_allocation() {
        let mut memory = FlatImageMemory::new();
        let lease = memory
            .allocate_image(AllocationRequest::new(Placement::Anywhere, 32, 8))
            .unwrap();
        let allocation = *lease.allocation();
        memory
            .write(&allocation, AllocationOffset::new(0), b"live")
            .unwrap();
        memory.service.lock().last_counter = u32::MAX - 1;
        let last = memory
            .allocate_image(AllocationRequest::new(Placement::Anywhere, 16, 8))
            .unwrap();
        memory.release_committed(last);

        for _ in 0..2 {
            assert!(memory
                .allocate_image(AllocationRequest::new(Placement::Anywhere, 16, 8))
                .is_err());
            assert_eq!(memory.service.lock().entries.len(), 1);
        }
        let mut bytes = [0; 4];
        memory
            .read(&allocation, AllocationOffset::new(0), &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"live");
        memory.release_committed(lease);
        assert!(memory.service.lock().entries.is_empty());
    }

    #[test]
    fn service_nonce_exhaustion_never_wraps() {
        let last = AtomicU32::new(0);
        assert_eq!(reserve_service_nonce(&last), Some(1));
        assert_eq!(reserve_service_nonce(&last), Some(2));

        let last = AtomicU32::new(u32::MAX - 1);
        assert_eq!(reserve_service_nonce(&last), Some(u32::MAX));
        for _ in 0..2 {
            assert_eq!(reserve_service_nonce(&last), None);
            assert_eq!(last.load(Ordering::Relaxed), u32::MAX);
        }
    }

    #[test]
    fn clones_share_a_counter_but_independent_services_have_distinct_nonces() {
        let mut memory = FlatImageMemory::new();
        let mut clone = memory.clone();
        let mut independent = FlatImageMemory::new();
        let request = AllocationRequest::new(Placement::Anywhere, 16, 8);
        let first = memory.allocate_image(request).unwrap();
        let second = clone.allocate_image(request).unwrap();
        let other = independent.allocate_image(request).unwrap();
        let first_id = first.allocation().id().value();
        let second_id = second.allocation().id().value();
        let other_id = other.allocation().id().value();
        assert_eq!(first_id & u64::from(u32::MAX), 1);
        assert_eq!(second_id & u64::from(u32::MAX), 2);
        assert_eq!(other_id & u64::from(u32::MAX), 1);
        assert_eq!(first_id >> 32, second_id >> 32);
        assert_ne!(first_id >> 32, other_id >> 32);

        clone.release_committed(first);
        memory.release_committed(second);
        independent.release_committed(other);
        assert!(memory.service.lock().entries.is_empty());
        assert!(independent.service.lock().entries.is_empty());
    }

    #[test]
    fn service_namespace_is_not_reused_after_drop() {
        let first_nonce = {
            let memory = FlatImageMemory::new();
            let nonce = memory.service.lock().nonce.expect("reserve namespace");
            nonce
        };
        let memory = FlatImageMemory::new();
        let next_nonce = memory.service.lock().nonce.expect("reserve namespace");
        assert_ne!(first_nonce, next_nonce);
    }

    #[test]
    fn exhausted_service_namespace_cannot_publish_allocations() {
        let mut memory = FlatImageMemory::new();
        memory.service.lock().nonce = None;
        for _ in 0..2 {
            assert!(memory
                .allocate_image(AllocationRequest::new(Placement::Anywhere, 16, 8))
                .is_err());
            let service = memory.service.lock();
            assert!(service.entries.is_empty());
            assert_eq!(service.last_counter, 0);
        }
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use blueos_test_macro::test;
    #[test]
    fn physical_pin_keeps_bytes_alive_after_unique_lease_release() {
        for abort in [false, true] {
            let mut memory = FlatImageMemory::new();
            let lease = memory
                .allocate_image(AllocationRequest::new(Placement::Anywhere, 32, 8))
                .unwrap();
            let allocation = *lease.allocation();
            memory
                .write(&allocation, AllocationOffset::new(0), b"pinned")
                .unwrap();
            let pin = memory.pin(&allocation).unwrap();
            let retained = pin.clone();
            if abort {
                memory.abort_image(lease, MutationProgress::BytesModified);
            } else {
                memory.release_committed(lease);
            }
            assert!(memory.service.lock().entries.is_empty());
            drop(pin);
            assert_eq!(&retained.0.storage.as_slice()[..6], b"pinned");
            assert!(memory
                .validate_range(&allocation, AllocationOffset::new(0), 6)
                .is_err());
            drop(retained);
        }
    }
}
