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

use crate::address::TargetAddress;

pub type LoadResult<T> = core::result::Result<T, LoadError>;

#[derive(Clone, Copy)]
pub(crate) enum LoadStage {
    Unknown,
    Read,
    Parse,
    Validate,
    Plan,
    Allocate,
    Map,
    Metadata,
    Relocate,
    Cache,
    Seal,
}

#[derive(Clone, Copy)]
pub(crate) enum LoadErrorKind {
    BadElf,
    UnsupportedByProfile,
    OutOfBounds,
    IntegerOverflow,
    ResourceLimit,
    OutOfMemory,
    InvalidAlignment,
    PermissionConflict,
    Backend,
    Io,
    SourceChanged,
}
pub(crate) enum HeaderField {
    Magic,
    Class,
    Endian,
    Version,
    OsAbi,
    Type,
    Machine,
    Flags,
    Entry,
    HeaderSize,
    ProgramHeaderSize,
    ProgramHeaderTable,
}
pub(crate) enum LimitKind {
    FileLength,
    ProgramHeaderCount,
    LoadSegmentCount,
    ImageSpan,
    SegmentAlignment,
    LayoutBytes,
    DynamicEntryCount,
    RelocationCount,
    RuntimeMetadataBytes,
    RelocationOperationBytes,
}
pub(crate) enum ProgramHeaderField {
    Type,
    FileRange,
    VirtualRange,
    DuplicateDynamic,
    DuplicateRelro,
    DuplicateStack,
    UnsupportedInterpreter,
    UnsupportedTls,
    ExecutableStack,
}

pub(crate) enum ErrorContext {
    None,
    FileRange {
        offset: u64,
        len: u64,
        file_len: u64,
    },
    HeaderField {
        field: HeaderField,
        value: u64,
    },
    TargetRange {
        start: TargetAddress,
        len: u64,
        align: u64,
    },
    ProgramHeader {
        index: u16,
        field: ProgramHeaderField,
        value: u64,
    },
    Allocation {
        base: TargetAddress,
        len: u64,
        align: u64,
    },
}

pub(crate) struct LoadError {
    stage: LoadStage,
    kind: LoadErrorKind,
    context: ErrorContext,
}

impl LoadError {
    #[inline]
    pub const fn new_without_stage(kind: LoadErrorKind, context: ErrorContext) -> Self {
        Self {
            stage: LoadStage::Unknown,
            kind,
            context,
        }
    }

    #[inline]
    pub const fn with_stage(mut self, stage: LoadStage) -> Self {
        self.stage = stage;
        self
    }

    #[inline]
    pub const fn stage(&self) -> LoadStage {
        self.stage
    }

    #[inline]
    pub const fn kind(&self) -> LoadErrorKind {
        self.kind
    }

    #[inline]
    pub const fn context(&self) -> &ErrorContext {
        &self.context
    }
}
