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

//! Immutable regular-file input captured atomically by its filesystem.
use crate::{
    error::{code, Error},
    vfs::File,
};
use alloc::vec::Vec;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    reader::ElfReader,
    LoadError, LoadResult,
};

pub struct VfsElfReader {
    bytes: Vec<u8>,
}
impl VfsElfReader {
    pub fn new(file: File) -> LoadResult<Self> {
        // This is the per-artifact input limit of the kernel's fixed load profile.
        let bytes = file
            .snapshot(64 * 1024 * 1024)
            .map_err(|e| map_error(e, 0, 0, 0))?;
        Ok(Self { bytes })
    }
}
impl ElfReader for VfsElfReader {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let len = dst.len() as u64;
        let at = usize::try_from(offset)
            .map_err(|_| map_error(code::EOVERFLOW, offset, len, self.bytes.len() as u64))?;
        let end = at
            .checked_add(dst.len())
            .ok_or_else(|| map_error(code::EOVERFLOW, offset, len, self.bytes.len() as u64))?;
        let source = self
            .bytes
            .get(at..end)
            .ok_or_else(|| map_error(code::ENODATA, offset, len, self.bytes.len() as u64))?;
        dst.copy_from_slice(source);
        Ok(())
    }
}
fn map_error(error: Error, offset: u64, len: u64, file_len: u64) -> LoadError {
    let kind = if error == code::ENOMEM {
        LoadErrorKind::OutOfMemory
    } else if error == code::EOVERFLOW {
        LoadErrorKind::IntegerOverflow
    } else if error == code::ENODATA {
        LoadErrorKind::OutOfBounds
    } else if error == code::EFBIG {
        LoadErrorKind::ResourceLimit
    } else {
        LoadErrorKind::Io
    };
    LoadError::new(
        kind,
        ErrorContext::FileRange {
            offset,
            len,
            file_len,
        },
    )
}
