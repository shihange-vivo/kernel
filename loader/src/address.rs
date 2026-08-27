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

use crate::{ErrorContext, LoadError, LoadErrorKind, LoadStage};

pub type RangeResult<T> = core::result::Result<T, RangeError>;

/// An address or range failure before a pipeline stage has claimed it.
///
/// Low-level checked arithmetic is shared by admission, mapping, relocation,
/// cache maintenance and sealing. Keeping it stage-neutral lets the caller
/// report the stage that actually consumed the untrusted value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeError {
    kind: LoadErrorKind,
    context: ErrorContext,
}

impl RangeError {
    pub const fn new(kind: LoadErrorKind, context: ErrorContext) -> Self {
        Self { kind, context }
    }

    pub const fn at(self, stage: LoadStage) -> LoadError {
        LoadError::new(stage, self.kind, self.context)
    }

    pub const fn kind(&self) -> LoadErrorKind {
        self.kind
    }

    pub const fn context(&self) -> &ErrorContext {
        &self.context
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetAddr(u64);

impl TargetAddr {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, value: u64) -> RangeResult<Self> {
        self.0.checked_add(value).map(Self).ok_or_else(|| {
            RangeError::new(
                LoadErrorKind::IntegerOverflow,
                ErrorContext::TargetRange {
                    start: self,
                    len: value,
                },
            )
        })
    }

    pub fn checked_sub(self, other: Self) -> RangeResult<u64> {
        self.0.checked_sub(other.0).ok_or_else(|| {
            RangeError::new(
                LoadErrorKind::IntegerOverflow,
                ErrorContext::TargetRange {
                    start: other,
                    len: self.0,
                },
            )
        })
    }

    pub fn align_down(self, align: u64) -> RangeResult<Self> {
        validate_alignment(align)?;
        Ok(Self(self.0 & !(align - 1)))
    }

    pub fn align_up(self, align: u64) -> RangeResult<Self> {
        validate_alignment(align)?;
        let mask = align - 1;
        Ok(Self(self.checked_add(mask)?.0 & !mask))
    }
}

fn validate_alignment(align: u64) -> RangeResult<()> {
    if align.is_power_of_two() {
        Ok(())
    } else {
        Err(alignment_error(0, align))
    }
}

fn alignment_error(value: u64, align: u64) -> RangeError {
    RangeError::new(
        LoadErrorKind::InvalidAlignment,
        ErrorContext::TargetRange {
            start: TargetAddr::new(value),
            len: align,
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetRange {
    start: TargetAddr,
    len: u64,
}

impl TargetRange {
    pub const fn new(start: TargetAddr, len: u64) -> Self {
        Self { start, len }
    }

    pub const fn start(self) -> TargetAddr {
        self.start
    }

    pub const fn len(self) -> u64 {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn end(self) -> RangeResult<TargetAddr> {
        self.start.checked_add(self.len)
    }

    pub fn contains_span(self, start: TargetAddr, len: u64) -> bool {
        let Ok(self_end) = self.end() else {
            return false;
        };
        let Ok(span_end) = start.checked_add(len) else {
            return false;
        };
        start >= self.start && span_end <= self_end
    }

    pub fn overlaps(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let (Ok(self_end), Ok(other_end)) = (self.end(), other.end()) else {
            return true;
        };
        self.start < other_end && other.start < self_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRange {
    offset: u64,
    len: u64,
}

impl FileRange {
    pub const fn new(offset: u64, len: u64) -> Self {
        Self { offset, len }
    }

    pub const fn offset(self) -> u64 {
        self.offset
    }

    pub const fn len(self) -> u64 {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn end(self) -> RangeResult<u64> {
        self.offset.checked_add(self.len).ok_or_else(|| {
            RangeError::new(
                LoadErrorKind::IntegerOverflow,
                ErrorContext::FileRange {
                    offset: self.offset,
                    len: self.len,
                    file_len: 0,
                },
            )
        })
    }

    pub fn validate(self, file_len: u64) -> RangeResult<()> {
        if self.end()? <= file_len {
            return Ok(());
        }
        Err(RangeError::new(
            LoadErrorKind::OutOfBounds,
            ErrorContext::FileRange {
                offset: self.offset,
                len: self.len,
                file_len,
            },
        ))
    }
}
