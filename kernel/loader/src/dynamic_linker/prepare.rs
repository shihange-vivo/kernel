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

//! Link already mapped images: freeze symbol scopes, relocate, synchronize
//! code caches and seal final memory protections.

use crate::{
    dynamic_linker::{LoadedSession, SealedSession},
    memory::{
        cache::{ArchitectureCodeCache, CacheRequirements},
        ImageProtectionMemory,
    },
    relocation::NativeRelocator,
    LoadResult,
};

pub(crate) fn prepare_link<M: ImageProtectionMemory + ?Sized>(
    images: LoadedSession<'_, M, NativeRelocator>,
) -> LoadResult<SealedSession<'_, M, NativeRelocator>> {
    let mut cache = ArchitectureCodeCache::new(CacheRequirements::CURRENT_EXECUTION_CONTEXT);
    images.freeze_scopes()?.relocate()?.seal(&mut cache)
}
