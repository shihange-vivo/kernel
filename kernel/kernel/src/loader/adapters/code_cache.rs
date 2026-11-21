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

//! Bind the loader's cache contract to native instruction publication.

use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    memory::TargetRange,
    CodeCache, LoadError, LoadResult,
};

/// Publishes executable ranges for the kernel's flat memory mapping.
pub struct KernelCodeCache;

impl KernelCodeCache {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for KernelCodeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeCache for KernelCodeCache {
    fn synchronize(&mut self, executable: TargetRange) -> LoadResult<()> {
        let end = executable.end()?;
        let context = || ErrorContext::TargetRange {
            start: executable.start(),
            len: executable.len(),
            align: 1,
        };
        let start = usize::try_from(executable.start().get())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        let end = usize::try_from(end.get())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        if start != end {
            let _preempt = crate::thread::Thread::try_preempt_me();
            // SAFETY: the loader retains the live flat mapping and preemption
            // stays disabled through local maintenance and remote notification.
            unsafe { crate::arch::instruction_cache::publish(start..end) };
        }
        Ok(())
    }
}
