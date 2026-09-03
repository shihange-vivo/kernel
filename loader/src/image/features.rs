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

use alloc::vec::Vec;
use goblin::elf::dynamic::{
    DF_1_NOW, DF_BIND_NOW, DT_BIND_NOW, DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS,
    DT_FLAGS_1, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTREL,
    DT_PLTRELSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_SONAME,
};

use crate::{
    dynamic_linker::ArtifactRole,
    elf::DynamicSegmentInfo,
    error::{LoadError, LoadErrorKind, LoadResult},
    identity::{ElfClass, ElfData, LoadLimits, LoadPolicy},
    image::map::{decode_dynamic_entry, dynamic_error, unsupported_dynamic},
    reader::ElfReader,
};

/// S1 summary of the dynamic features an image requests.
///
/// Produced from the file-backed `PT_DYNAMIC` before any allocation or write.
/// It records raw `DT_NEEDED`/`DT_SONAME` string-table offsets rather than
/// resolving them: full dynstr decoding is deferred to S4, but the presence of
/// every phase-gated feature is decided here so an unsupported image never
/// reaches allocation.
pub(crate) struct DynamicFeatureSummary {
    needed: Vec<u64>,
    soname: Option<u64>,
    has_plt_relocations: bool,
    has_lifecycle: bool,
}

impl DynamicFeatureSummary {
    pub(crate) const fn empty() -> Self {
        Self {
            needed: Vec::new(),
            soname: None,
            has_plt_relocations: false,
            has_lifecycle: false,
        }
    }

    #[inline]
    pub(crate) fn needed(&self) -> &[u64] {
        &self.needed
    }

    #[inline]
    pub(crate) const fn soname(&self) -> Option<u64> {
        self.soname
    }

    #[inline]
    pub(crate) const fn has_plt_relocations(&self) -> bool {
        self.has_plt_relocations
    }

    #[inline]
    pub(crate) const fn has_lifecycle(&self) -> bool {
        self.has_lifecycle
    }
}

/// S1 stage 2: scan the file-backed `PT_DYNAMIC` and return a feature summary,
/// rejecting any tag the policy does not permit.
///
/// This runs before allocation, so a policy violation (`DT_NEEDED` under
/// Phase 0, `RPATH/RUNPATH`, symbol versioning, unknown tags, …) fails with
/// zero allocations and zero writes.
pub(crate) fn validate_dynamic_features<R: ElfReader>(
    reader: &R,
    dynamic: &DynamicSegmentInfo,
    policy: LoadPolicy,
    role: ArtifactRole,
    class: ElfClass,
    endian: ElfData,
    limits: &LoadLimits,
) -> LoadResult<DynamicFeatureSummary> {
    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    let file_range = dynamic.file_range();
    if file_range.is_empty() || file_range.len() % entry_size != 0 {
        return Err(dynamic_error(DT_NULL, file_range.len()));
    }
    if file_range.len() > dynamic.memory_size() {
        return Err(dynamic_error(DT_NULL, file_range.len()));
    }

    let entry_count = file_range.len() / entry_size;
    let mut needed = Vec::new();
    needed
        .try_reserve_exact(entry_count as usize)
        .map_err(|_| {
            LoadError::new(LoadErrorKind::OutOfMemory, crate::error::ErrorContext::None)
        })?;
    let mut soname = None;
    let mut has_plt_relocations = false;
    let mut bind_now = false;
    let mut has_lifecycle = false;

    let mut raw = [0; 16];
    let mut terminated = false;
    for index in 0..entry_count {
        limits.check_dynamic_entry_count(index + 1)?;
        let offset = file_range
            .offset()
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::IntegerOverflow,
                    crate::error::ErrorContext::DynamicTag {
                        tag: DT_NULL,
                        value: index,
                    },
                )
            })?)
            .ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::IntegerOverflow,
                    crate::error::ErrorContext::DynamicTag {
                        tag: DT_NULL,
                        value: index,
                    },
                )
            })?;
        reader.read_exact_at(offset, &mut raw[..entry_size as usize])?;
        let (tag, value) = decode_dynamic_entry(&raw[..entry_size as usize], class, endian)?;
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        if !policy.allows_dynamic_tag(tag, value) {
            return Err(unsupported_dynamic(tag, value));
        }
        match tag {
            DT_NEEDED => needed.push(value),
            DT_SONAME => {
                if soname.replace(value).is_some() {
                    return Err(dynamic_error(DT_SONAME, value));
                }
            }
            DT_PLTRELSZ | DT_PLTREL | DT_JMPREL => has_plt_relocations = true,
            DT_BIND_NOW => bind_now = true,
            DT_FLAGS if value & DF_BIND_NOW != 0 => bind_now = true,
            DT_FLAGS_1 if value & DF_1_NOW != 0 => bind_now = true,
            DT_INIT | DT_FINI | DT_INIT_ARRAY | DT_FINI_ARRAY | DT_INIT_ARRAYSZ
            | DT_FINI_ARRAYSZ | DT_PREINIT_ARRAY | DT_PREINIT_ARRAYSZ => has_lifecycle = true,
            _ => {}
        }
    }
    if !terminated {
        return Err(dynamic_error(DT_NULL, file_range.len()));
    }

    // A shared object must advertise a bounded, NUL-terminated SONAME; only the
    // root may omit it. The offset itself is bounds-checked against `DT_STRSZ`
    // later, in S4.
    if role == ArtifactRole::SharedObject && soname.is_none() {
        return Err(dynamic_error(DT_SONAME, 0));
    }
    if has_plt_relocations && policy.requires_now_for_plt() && !bind_now {
        return Err(unsupported_dynamic(DT_JMPREL, 0));
    }

    Ok(DynamicFeatureSummary {
        needed,
        soname,
        has_plt_relocations,
        has_lifecycle,
    })
}
