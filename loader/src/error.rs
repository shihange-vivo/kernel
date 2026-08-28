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

pub type LoadResult<T> = core::result::Result<T, LoadError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LoadStage {
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
    Publish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LoadErrorKind {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderField {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitKind {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProgramHeaderField {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorContext {
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
        start: crate::TargetAddr,
        len: u64,
    },
    ProgramHeader {
        index: u16,
        field: ProgramHeaderField,
        value: u64,
    },
    Allocation {
        base: crate::TargetAddr,
        len: u64,
        align: u64,
    },
    MemoryAccess {
        allocation: crate::AllocationId,
        offset: u64,
        len: u64,
    },
    DynamicTag {
        tag: u64,
        value: u64,
    },
    Relocation {
        offset: crate::TargetAddr,
        raw_type: u32,
        symbol_index: u32,
    },
    Limit {
        resource: LimitKind,
        actual: u64,
        maximum: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadError {
    stage: LoadStage,
    kind: LoadErrorKind,
    context: ErrorContext,
}

impl LoadError {
    pub const fn new(stage: LoadStage, kind: LoadErrorKind, context: ErrorContext) -> Self {
        Self {
            stage,
            kind,
            context,
        }
    }

    pub const fn stage(&self) -> LoadStage {
        self.stage
    }

    pub const fn kind(&self) -> LoadErrorKind {
        self.kind
    }

    pub const fn context(&self) -> &ErrorContext {
        &self.context
    }

    pub(crate) const fn with_stage(mut self, stage: LoadStage) -> Self {
        self.stage = stage;
        self
    }
}
