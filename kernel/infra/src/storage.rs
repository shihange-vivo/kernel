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

extern crate alloc;
use core::{
    alloc::Layout,
    option::Option::{self, Some},
};

#[derive(Debug)]
#[must_use = "keep the storage owner alive while its allocation is in use"]
pub enum Storage {
    Alloc(*mut u8, Layout),
    Raw(*mut u8, usize),
}

impl Default for Storage {
    fn default() -> Self {
        Self::Raw(core::ptr::null_mut(), 0)
    }
}

impl Storage {
    #[inline]
    pub fn from_layout(layout: Layout) -> Self {
        let base = unsafe { alloc::alloc::alloc(layout) };
        Storage::Alloc(base, layout)
    }

    #[inline]
    pub fn try_from_layout(layout: Layout) -> Option<Self> {
        if layout.size() == 0 {
            return None;
        }
        // SAFETY: Layout validates alignment and representable size; the
        // nonzero check above satisfies alloc's additional precondition.
        let base = unsafe { alloc::alloc::alloc(layout) };
        if base.is_null() {
            None
        } else {
            Some(Storage::Alloc(base, layout))
        }
    }

    // This API is designed to be used by memory allocated by FFI, so
    // invoker of this API is responsible to guarantee the safety.
    #[inline]
    pub unsafe fn from_raw(base: *mut u8, size: usize) -> Self {
        Storage::Raw(base, size)
    }

    #[inline]
    pub const fn new() -> Self {
        Storage::Raw(core::ptr::null_mut(), 0)
    }

    #[inline]
    pub fn base(&self) -> *mut u8 {
        match self {
            Storage::Alloc(base, _) => *base,
            Storage::Raw(base, _) => *base,
        }
    }

    #[inline]
    pub fn size(&self) -> usize {
        match self {
            Storage::Alloc(_, layout) => layout.size(),
            Storage::Raw(_, size) => *size,
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.base(), self.size()) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.base(), self.size()) }
    }
}

impl Drop for Storage {
    #[inline]
    fn drop(&mut self) {
        if let Storage::Alloc(base, layout) = self {
            unsafe { alloc::alloc::dealloc(*base, *layout) }
        }
    }
}

// FIXME: Workaround for pointer based storage.
unsafe impl Send for Storage {}
unsafe impl Sync for Storage {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallible_storage_rejects_zero_sized_layouts() {
        for alignment in [1, 8, 64] {
            let layout = Layout::from_size_align(0, alignment).unwrap();
            assert!(Storage::try_from_layout(layout).is_none());
        }
    }

    #[test]
    fn fallible_storage_keeps_the_requested_layout() {
        let layout = Layout::from_size_align(32, 16).unwrap();
        let storage = Storage::try_from_layout(layout).expect("allocate test storage");
        assert_eq!(storage.size(), 32);
        assert!(storage.base().is_aligned_to(16));
        // SAFETY: storage uniquely owns this nonempty block; initialize all
        // bytes before observing them through its shared slice view.
        unsafe { core::ptr::write_bytes(storage.base(), 0xa5, storage.size()) };
        assert_eq!(storage.as_slice(), &[0xa5; 32]);
    }
}
