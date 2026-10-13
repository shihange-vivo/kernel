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

//! Host services and ownership contracts for a complete load.

use alloc::vec::Vec;

use crate::{
    memory::ImageProtectionMemory, reader::ElfReader, trace::LoadEvent, CommittedAllocations,
    ImageDependency, ImageHandle, LoadResult, LoadedImage, Publication,
};

/// Platform services used by a complete load.
///
/// The loader owns ELF parsing, dependency traversal, scopes and relocation.
/// The backend owns file lookup policy, allocation backing and registry state.
/// The memory value must be a handle to backing that outlives the returned receipt.
pub trait LoaderBackend {
    type Source: Clone;
    type Reader: ElfReader;
    type Memory: ImageProtectionMemory;
    type PreparedPublication;
    type Receipt;

    /// Stable identity bytes for a source, including any generation policy.
    fn identity<'a>(&self, source: &'a Self::Source) -> &'a [u8];
    /// Whether the source is managed by the shared-image registry.
    /// Registry sources must be ET_DYN shared objects; executables and marked
    /// PIEs are rejected before `acquire` reserves their registry state.
    fn is_shared(&self, source: &Self::Source) -> bool;
    fn open(&mut self, source: &Self::Source) -> LoadResult<Self::Reader>;
    /// Return an already loaded image without opening its ELF. Retain its
    /// backing until publication or cancellation. This must not reserve a new
    /// load permit: closure discovery precedes the atomic acquire below.
    fn snapshot(&mut self, source: &Self::Source) -> LoadResult<Option<ImageHandle>>;
    /// Locate one dependency. A present but invalid file must not fall back.
    fn resolve(&mut self, requester: &Self::Source, name: &[u8]) -> LoadResult<Self::Source>;
    /// Restore an exact source from a published dependency snapshot, without
    /// repeating path search or probing the file. Identity and sharing policy
    /// must match the snapshot; its loaded provider must remain available.
    fn resolve_snapshot(&mut self, dependency: &ImageDependency) -> LoadResult<Self::Source>;
    /// Reserve the complete closure atomically before any image is mapped.
    /// Return Ready handles for these sources and retain their backing leases
    /// until publication. `existing` is already pinned by the caller, including
    /// providers whose constructors may still be running in this namespace.
    /// A Ready result must also be visible to `snapshot` on a later probe:
    /// if publication raced discovery and changed its closure, the loader
    /// cancels this batch and retries against the immutable Ready snapshot.
    fn acquire(
        &mut self,
        sources: &[Self::Source],
        existing: &[ImageHandle],
    ) -> LoadResult<Vec<ImageHandle>>;
    fn memory(&mut self) -> Self::Memory;
    fn prepare_publication(
        &mut self,
        publication: &Publication,
    ) -> LoadResult<Self::PreparedPublication>;
    /// Transfer allocation ownership after all fallible publication work.
    ///
    /// # Safety
    /// These inputs belong to this backend's current load. This operation must
    /// not allocate, fail or panic, and must retain every allocation exactly once.
    unsafe fn commit_publication(
        &mut self,
        prepared: Self::PreparedPublication,
        allocations: CommittedAllocations,
    ) -> Self::Receipt;
    /// Install registry state using the loader's computed retention facts.
    /// On error, leave remaining allocation authority in the receipt so
    /// `abort_publication` can release it. Constructors run after `load` returns.
    fn complete_load(&mut self, _image: &mut LoadedImage<Self::Receipt>) -> LoadResult<()> {
        Ok(())
    }
    /// Release a committed receipt if completion failed before installation.
    fn abort_publication(&mut self, receipt: Self::Receipt);
    /// Cancel remaining reservations and imported references on a failed load.
    fn cancel_load(&mut self) {}
    /// Opt into load observations. Disabled by default; detailed product walks
    /// are skipped when disabled. Keep this choice stable during one load.
    fn trace_enabled(&self) -> bool {
        false
    }
    /// Synchronous, borrowed observations; no internal graph or relocation
    /// types cross this hook. Copy fields before retaining them. The observer
    /// must not panic or reenter loading, and must not change load ownership.
    /// It is called outside the infallible allocation-commit operation.
    fn trace(&self, _event: LoadEvent<'_>) {}
}
