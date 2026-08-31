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

use core::fmt::Debug;

use crate::address::TargetAddress;

pub type LoadResult<T> = core::result::Result<T, LoadError>;

#[derive(Clone, Copy, Debug)]
pub(crate) enum LoadStage {
    Admit,
    Inspect,
    Plan,
    Allocate,
    Map,
    Decode,
    Relocate,
    Cache,
    Seal,
}

#[derive(Clone, Copy, Debug)]
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
    IncorrectLayout,
    NotAllocated,
}

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Debug)]
pub(crate) enum ProgramHeaderField {
    Type,
    FileRange,
    VirtualRange,
    DuplicateDynamic,
    DuplicateRelro,
    DuplicateStack,
    DuplicateInterpreter,
    DuplicateTls,
    UnsupportedInterpreter,
    UnsupportedTls,
    ExecutableStack,
    Align,
    UnknownField,
}

#[non_exhaustive]
#[derive(Debug)]
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
    MemoryAccess {
        allocation_base: TargetAddress,
        allocation_len: u64,
        allocation_align: u64,
        offset: u64,
        len: u64,
    },
    DynamicTag {
        tag: u64,
        len: u64,
    },
    Relocation {
        offset: TargetAddress,
        raw_type: u32,
        symbol_index: u32,
    },
    Limit {
        resource: LimitKind,
        actual: u64,
        maximum: u64,
    },
}

pub(crate) struct LoadError {
    stage: Option<LoadStage>,
    kind: LoadErrorKind,
    context: ErrorContext,
}

impl LoadError {
    #[inline]
    pub const fn new(kind: LoadErrorKind, context: ErrorContext) -> Self {
        Self {
            stage: None,
            kind,
            context,
        }
    }

    #[inline]
    pub const fn at_stage(mut self, stage: LoadStage) -> Self {
        if self.stage.is_none() {
            self.stage = Some(stage)
        }
        self
    }

    #[inline]
    pub const fn stage(&self) -> Option<LoadStage> {
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

impl Debug for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("LoadError");

        match self.stage {
            Some(stage) => {
                debug.field("stage", &stage);
            }
            None => {
                debug.field("stage", &"<stage not attached>");
            }
        }

        debug
            .field("kind", &self.kind)
            .field("context", &self.context)
            .finish()
    }
}
