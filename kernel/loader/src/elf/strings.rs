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

//! Bounded access to ELF dynamic string table entries.

use super::FileRange;
#[cfg(any(test, enable_dynamic_linker))]
use crate::{
    error::{ErrorContext, LoadErrorKind},
    ElfReader, LoadError, LoadResult,
};
#[cfg(any(test, enable_dynamic_linker))]
use alloc::vec::Vec;
#[cfg(any(test, enable_dynamic_linker))]
use goblin::elf::dynamic::DT_STRTAB;

/// Bytes available for a string and its terminator starting at this table index.
pub(super) fn string_range(table: FileRange, offset: u64) -> Option<FileRange> {
    let len = table.len().checked_sub(offset)?;
    if len == 0 {
        return None;
    }
    Some(FileRange::new(table.offset().checked_add(offset)?, len))
}

/// Read a NUL-terminated name within the table and the caller's length budget.
/// The returned bytes exclude the terminator and may contain non-UTF-8 data.
#[cfg(any(test, enable_dynamic_linker))]
pub(crate) fn read_string(
    reader: &impl ElfReader,
    table: FileRange,
    offset: u64,
    max_len: u32,
) -> LoadResult<Vec<u8>> {
    let fail = |kind| {
        LoadError::new(
            kind,
            ErrorContext::DynamicTag {
                tag: DT_STRTAB,
                value: offset,
            },
        )
    };
    let range = string_range(table, offset).ok_or_else(|| fail(LoadErrorKind::BadElf))?;
    // Allow one extra byte for a terminator at the exact length limit.
    let max_len = u64::from(max_len);
    let scan_len = range.len().min(max_len + 1);
    let end = range
        .offset()
        .checked_add(scan_len)
        .ok_or_else(|| fail(LoadErrorKind::IntegerOverflow))?;
    let mut position = range.offset();
    let mut name = Vec::new();
    let mut buffer = [0; 64];
    while position < end {
        let chunk_len = (end - position).min(buffer.len() as u64) as usize;
        let chunk = &mut buffer[..chunk_len];
        reader.read_exact_at(position, chunk)?;

        let terminator = chunk.iter().position(|&byte| byte == 0);
        let len = terminator.unwrap_or(chunk.len());
        if position - range.offset() + len as u64 > max_len {
            return Err(fail(LoadErrorKind::ResourceLimit));
        }
        name.try_reserve(len)
            .map_err(|_| fail(LoadErrorKind::OutOfMemory))?;
        name.extend_from_slice(&chunk[..len]);
        if terminator.is_some() {
            return Ok(name);
        }
        position += chunk_len as u64;
    }
    Err(fail(LoadErrorKind::BadElf))
}
