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

//! `ElfReader` adapter over an already-admitted VFS file (C23-b, §12.2).
//!
//! [`VfsElfReader`] binds the loader's neutral [`ElfReader`] contract to a
//! concrete [`File`]: it never accepts a bare path, never reads or mutates the
//! shared file offset, and freezes a [`FileSnapshotId`] at construction.
//! Every read re-validates the content generation; a mid-load write or
//! truncate is reported as [`LoadErrorKind::SourceChanged`] so the not-yet
//! published link session can roll back completely instead of loading a mixed
//! version (§11.2).

use crate::{
    error::{code, Error},
    vfs::{File, FileOps, FileSnapshotId},
};
use blueos_loader::{ElfReader, ErrorContext, LoadError, LoadErrorKind, LoadResult};

/// A read-only ELF reader over a fixed VFS file snapshot.
///
/// The reader holds the `File` by value: its positional reads go through the
/// `FileOps` layer and leave `File.offset` untouched, so two readers can
/// interleave reads of the same inode without interference (§11.3).
pub struct VfsElfReader {
    file: File,
    snapshot: FileSnapshotId,
}

impl VfsElfReader {
    /// Admit `file` and freeze its current content snapshot.
    ///
    /// The caller (the resolver) is responsible for admitting only trusted,
    /// immutable or catalog-backed sources (§11.2); this constructor merely
    /// records the token that later reads are validated against.
    pub fn new(file: File) -> Self {
        let snapshot = file.snapshot_id();
        Self { file, snapshot }
    }

    /// The snapshot token frozen at construction.
    #[inline]
    pub const fn snapshot_id(&self) -> FileSnapshotId {
        self.snapshot
    }

    /// Re-validate the content generation against the frozen snapshot.
    fn check_generation(&self) -> LoadResult<()> {
        if self.file.snapshot_id().content_generation != self.snapshot.content_generation {
            return Err(source_changed());
        }
        Ok(())
    }
}

impl ElfReader for VfsElfReader {
    fn len(&self) -> LoadResult<u64> {
        self.check_generation()?;
        self.file
            .len()
            .map_err(|error| map_error(error, 0, 0, self.snapshot.len))
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        self.check_generation()?;
        let len = u64::try_from(dst.len())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None))?;
        self.file
            .read_exact_at(offset, dst)
            .map_err(|error| map_error(error, offset, len, self.snapshot.len))?;
        // A write or truncate that raced the read is a changed source, even if
        // the read itself succeeded.
        self.check_generation()
    }
}

fn source_changed() -> LoadError {
    LoadError::new(LoadErrorKind::SourceChanged, ErrorContext::None)
}

/// Classify a kernel VFS error into a stable loader error (§11.3): a short
/// read at EOF maps to `OutOfBounds`, an offset overflow to
/// `IntegerOverflow`, a device I/O failure to `Io`, and anything else to
/// `Backend`.
fn map_error(error: Error, offset: u64, len: u64, file_len: u64) -> LoadError {
    let kind = if error == code::EIO {
        LoadErrorKind::Io
    } else if error == code::EOVERFLOW {
        LoadErrorKind::IntegerOverflow
    } else if error == code::ENODATA {
        LoadErrorKind::OutOfBounds
    } else {
        LoadErrorKind::Backend
    };
    LoadError::new(kind, ErrorContext::FileRange {
        offset,
        len,
        file_len,
    })
}
