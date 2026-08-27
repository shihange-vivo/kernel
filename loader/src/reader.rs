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

use crate::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage};

/// Identifies the immutable source version observed by an [`ElfReader`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceSnapshot(u64);

impl SourceSnapshot {
    pub const STABLE: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Random-access view of one immutable ELF source snapshot.
///
/// Adapters backed by mutable files must pin a vnode/version for the lifetime
/// of this value. If the source version changes, `snapshot` must return a new
/// token so the loader can fail with `SourceChanged`.
pub trait ElfReader {
    fn snapshot(&self) -> LoadResult<SourceSnapshot>;

    fn len(&self) -> LoadResult<u64>;

    fn is_empty(&self) -> LoadResult<bool> {
        Ok(self.len()? == 0)
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()>;
}

#[derive(Clone, Copy, Debug)]
pub struct SliceElfReader<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceElfReader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl ElfReader for SliceElfReader<'_> {
    fn snapshot(&self) -> LoadResult<SourceSnapshot> {
        Ok(SourceSnapshot::STABLE)
    }

    fn len(&self) -> LoadResult<u64> {
        u64::try_from(self.bytes.len()).map_err(|_| {
            LoadError::new(
                LoadStage::Read,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::None,
            )
        })
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let file_len = self.len()?;
        let len = u64::try_from(dst.len()).map_err(|_| {
            LoadError::new(
                LoadStage::Read,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::FileRange {
                    offset,
                    len: u64::MAX,
                    file_len,
                },
            )
        })?;
        let end = offset.checked_add(len).ok_or_else(|| {
            LoadError::new(
                LoadStage::Read,
                LoadErrorKind::IntegerOverflow,
                ErrorContext::FileRange {
                    offset,
                    len,
                    file_len,
                },
            )
        })?;
        if end > file_len {
            return Err(LoadError::new(
                LoadStage::Read,
                LoadErrorKind::OutOfBounds,
                ErrorContext::FileRange {
                    offset,
                    len,
                    file_len,
                },
            ));
        }

        let start = usize::try_from(offset).map_err(|_| {
            LoadError::new(
                LoadStage::Read,
                LoadErrorKind::OutOfBounds,
                ErrorContext::FileRange {
                    offset,
                    len,
                    file_len,
                },
            )
        })?;
        let end = usize::try_from(end).map_err(|_| {
            LoadError::new(
                LoadStage::Read,
                LoadErrorKind::OutOfBounds,
                ErrorContext::FileRange {
                    offset,
                    len,
                    file_len,
                },
            )
        })?;
        dst.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
}
