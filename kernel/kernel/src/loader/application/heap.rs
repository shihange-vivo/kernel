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

//! Track application malloc-family blocks without changing the heap's pointer ABI.
//! Static libc/std objects do not run Rust Drop when their ELF is unmapped. Free
//! their remaining blocks only after every member and deferred C cleanup finishes.
//! Kernel allocations and malloc calls outside an application remain independent.

use super::{Group, MEMBERS};
use crate::{allocator, scheduler};
use alloc::sync::Arc;
use core::ptr;

fn current_group() -> Option<Arc<Group>> {
    let members = MEMBERS.irqsave_lock();
    // malloc is also used before scheduler initialization, when no group exists.
    if members.is_empty() {
        return None;
    }
    members.get(&scheduler::current_thread_id()).cloned()
}

fn allocation_owner(address: usize) -> Option<Arc<Group>> {
    if let Some(group) = current_group()
        && group.state.irqsave_lock().allocations.contains(&address)
    {
        return Some(group);
    }
    // Deferred pthread cleanup runs on a kernel worker outside the group. Its
    // member remains registered until the callback returns, so it can free or
    // resize the original group's blocks without a second global registry.
    MEMBERS
        .irqsave_lock()
        .values()
        .find(|group| group.state.irqsave_lock().allocations.contains(&address))
        .cloned()
}

impl Group {
    fn allocate_heap(&self, size: usize, align: usize) -> *mut u8 {
        let mut state = self.state.irqsave_lock();
        // Reserve bookkeeping first: allocation failure must not leak a block
        // or turn an otherwise fallible malloc into an allocation-error panic.
        if state.allocations.try_reserve(1).is_err() {
            return ptr::null_mut();
        }
        let block = allocator::malloc_align(size, align);
        if !block.is_null() {
            state.allocations.push(block.expose_provenance());
        }
        block
    }
}

pub(crate) fn allocate_heap(size: usize, align: usize) -> *mut u8 {
    match current_group() {
        Some(group) => group.allocate_heap(size, align),
        None => allocator::malloc_align(size, align),
    }
}

pub(crate) fn free_heap(block: *mut u8) {
    if block.is_null() {
        return;
    }
    if let Some(group) = allocation_owner(block.addr()) {
        let mut state = group.state.irqsave_lock();
        let index = state
            .allocations
            .iter()
            .position(|&a| a == block.addr())
            .unwrap();
        state.allocations.swap_remove(index);
    }
    allocator::free(block);
}

pub(crate) fn reallocate_heap(old: *mut u8, size: usize, align: usize) -> *mut u8 {
    if old.is_null() {
        return allocate_heap(size, align);
    }
    let Some(group) = allocation_owner(old.addr()) else {
        // Resizing an incoming, untracked allocation does not transfer ownership.
        return allocator::realloc_align(old, size, align);
    };
    let mut state = group.state.irqsave_lock();
    let index = state
        .allocations
        .iter()
        .position(|&a| a == old.addr())
        .unwrap();
    // Hold the owner lock through resizing: a moved old address may immediately
    // be reused by another member. Failure preserves both the block and record.
    let block = allocator::realloc_align(old, size, align);
    if size == 0 {
        state.allocations.swap_remove(index);
    } else if !block.is_null() {
        state.allocations[index] = block.expose_provenance();
    }
    block
}
