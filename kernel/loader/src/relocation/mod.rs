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

//! Relocation operations and checked writes.

pub(crate) mod write;

use crate::{
    elf::RelocationRecord, error::LoadErrorKind, profile::LoadProfile, LoadError, LoadResult,
};

/// A symbol relocation classified by the load profile, with its effective addend.
#[cfg(enable_dynamic_linker)]
pub(crate) enum SymbolRelocation {
    Address(i64),
    JumpSlot(i64),
}

/// Calculate a standalone relocation value, or return `None` for a no-op.
pub(crate) fn relative_value(
    profile: &LoadProfile,
    bias: i128,
    record: &RelocationRecord,
) -> LoadResult<Option<i128>> {
    let Some(addend) = profile.check_relative_relocation(record)? else {
        return Ok(None);
    };
    if record.symbol_index() != 0 {
        return Err(LoadError::relocation(record, LoadErrorKind::BadElf));
    }
    Ok(Some(bias + i128::from(addend)))
}
