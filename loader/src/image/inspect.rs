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

use alloc::boxed::Box;

use crate::{
    address::{FileRange, TargetRange},
    elf::{DynamicSegmentInfo, ElfHeaderInfo, LoadSegmentInfo},
    reader::ElfReader,
};

#[derive(PartialEq)]
pub(crate) enum StackKind {
    NotDeclared,
    NonExecutable,
    Executable,
}

pub(crate) struct InspectedImage<R: ElfReader> {
    reader: R,
    header: ElfHeaderInfo,
    load_segments: Box<[LoadSegmentInfo]>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack: StackKind,
    interpreter: Option<FileRange>,
    tls: Option<TargetRange>,
}

impl<R: ElfReader> InspectedImage<R> {
    #[inline]
    pub const fn new(
        reader: R,
        header: ElfHeaderInfo,
        load_segments: Box<[LoadSegmentInfo]>,
        dynamic: Option<DynamicSegmentInfo>,
        relro: Option<TargetRange>,
        stack: StackKind,
        interpreter: Option<FileRange>,
        tls: Option<TargetRange>,
    ) -> Self {
        Self {
            reader,
            header,
            load_segments,
            dynamic,
            relro,
            stack,
            interpreter,
            tls,
        }
    }
}
