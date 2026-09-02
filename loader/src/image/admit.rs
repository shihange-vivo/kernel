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

use alloc::vec::Vec;
use goblin::{
    elf::program_header::{
        PF_R, PF_W, PF_X, PT_ARM_EXIDX, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK,
        PT_INTERP, PT_LOAD, PT_PHDR, PT_TLS,
    },
    elf64,
};

const PT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;

use crate::{
    address::{FileRange, TargetAddress, TargetRange},
    elf::{DynamicSegmentInfo, ElfHeaderInfo, LoadSegmentInfo, ProgramHeaderInfo},
    error::{ErrorContext, LoadError, LoadErrorKind, LoadResult, LoadStage, ProgramHeaderField},
    identity::{ElfMachine, LoadRequest, PHASE0_LOAD_POLICY},
    image::inspect::{InspectedImage, StackKind},
    reader::ElfReader,
    MemoryPermissions,
};

pub(crate) struct AdmittedImage<R: ElfReader> {
    reader: R,
    header: ElfHeaderInfo,
    request: LoadRequest,
    file_len: u64,
}

impl<R: ElfReader> AdmittedImage<R> {
    #[inline]
    pub const fn new(
        reader: R,
        header: ElfHeaderInfo,
        request: LoadRequest,
        file_len: u64,
    ) -> Self {
        Self {
            reader,
            header,
            request,
            file_len,
        }
    }

    pub fn inspect(self) -> LoadResult<InspectedImage<R>> {
        let count = self.header.program_header_count();
        self.request
            .limits()
            .check_load_segment_count(count.into())
            .map_err(|error| error.at_stage(LoadStage::Inspect))?;
        let mut load_segments = Vec::new();
        load_segments
            .try_reserve_exact(usize::from(count))
            .map_err(|_| {
                LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
                    .at_stage(LoadStage::Inspect)
            })?;

        let entry_size = usize::from(self.header.program_header_entry_size());
        let mut raw = [0; elf64::program_header::SIZEOF_PHDR];
        let mut dynamic = None;
        let mut relro = None;
        let mut stack = StackKind::NotDeclared;
        let mut interpreter = None;
        let mut tls = None;

        for index in 0..count {
            let offset = self
                .header
                .program_header_offset()
                .checked_add(u64::from(index) * u64::from(self.header.program_header_entry_size()))
                .ok_or_else(|| {
                    program_header_error(index, ProgramHeaderField::FileRange, 0)
                        .at_stage(LoadStage::Inspect)
                })?;
            self.reader
                .read_exact_at(offset, &mut raw[..entry_size])
                .map_err(|error| error.at_stage(LoadStage::Inspect))?;
            let program_header = ProgramHeaderInfo::decode(
                &raw[..entry_size],
                self.request.profile().class(),
                self.request.profile().endian(),
            )
            .map_err(|e| e.at_stage(LoadStage::Inspect))?;

            match program_header.r#type() {
                PT_LOAD => {
                    if program_header.file_size() > program_header.memory_size() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::FileRange,
                            program_header.file_size(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    TargetRange::new(program_header.vaddr(), program_header.memory_size())
                        .end()
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    load_segments.push(LoadSegmentInfo::new(
                        index,
                        file_range,
                        program_header.vaddr(),
                        program_header.memory_size(),
                        program_header.align(),
                        permissions_from_flags(program_header.flags()),
                    ));
                }
                PT_DYNAMIC => {
                    if dynamic.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateDynamic,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    TargetRange::new(program_header.vaddr(), program_header.memory_size())
                        .end()
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    dynamic = Some(DynamicSegmentInfo::new(
                        file_range,
                        program_header.vaddr(),
                        program_header.memory_size(),
                    ))
                }
                PT_GNU_RELRO => {
                    if relro.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateRelro,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let target_range =
                        TargetRange::new(program_header.vaddr(), program_header.memory_size());
                    target_range
                        .end()
                        .map_err(|error| error.at_stage(LoadStage::Inspect))?;
                    relro = Some(target_range);
                }
                PT_GNU_STACK => {
                    if stack != StackKind::NotDeclared {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateStack,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    if program_header.flags() & PF_X != 0 {
                        stack = StackKind::Executable;
                    } else {
                        stack = StackKind::NonExecutable
                    }
                }
                PT_INTERP => {
                    if interpreter.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateInterpreter,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    interpreter = Some(file_range);
                }
                PT_TLS => {
                    if tls.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateTls,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    if program_header.file_size() > program_header.memory_size() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::FileRange,
                            program_header.file_size(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    let target_range =
                        TargetRange::new(program_header.vaddr(), program_header.memory_size());
                    target_range
                        .end()
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    tls = Some(target_range)
                }
                PT_PHDR | PT_GNU_EH_FRAME => {}
                PT_ARM_EXIDX if self.header.machine() == ElfMachine::Arm => {}
                PT_RISCV_ATTRIBUTES if self.header.machine() == ElfMachine::Riscv => {}
                t => {
                    if !PHASE0_LOAD_POLICY.allows_unknown_program_headers() {
                        return Err(LoadError::new(
                            LoadErrorKind::UnsupportedByProfile,
                            ErrorContext::ProgramHeader {
                                index,
                                field: ProgramHeaderField::UnknownField,
                                value: t.into(),
                            },
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                }
            }
        }
        if !PHASE0_LOAD_POLICY.allows_executable_stack() && stack == StackKind::Executable {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ProgramHeader {
                    index: 0,
                    field: ProgramHeaderField::ExecutableStack,
                    value: 0,
                },
            )
            .at_stage(LoadStage::Inspect));
        }
        if !PHASE0_LOAD_POLICY.allows_interpreter() && interpreter.is_some() {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ProgramHeader {
                    index: 0,
                    field: ProgramHeaderField::UnsupportedInterpreter,
                    value: 0,
                },
            )
            .at_stage(LoadStage::Inspect));
        }
        if !PHASE0_LOAD_POLICY.allows_tls() && tls.is_some() {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ProgramHeader {
                    index: 0,
                    field: ProgramHeaderField::UnsupportedTls,
                    value: 0,
                },
            )
            .at_stage(LoadStage::Inspect));
        }

        Ok(InspectedImage::new(
            self.reader,
            self.request,
            self.header,
            load_segments.into_boxed_slice(),
            dynamic,
            relro,
            stack,
            interpreter,
            tls,
        ))
    }
}

fn permissions_from_flags(flags: u32) -> MemoryPermissions {
    let mut permissions = MemoryPermissions::NONE;
    if flags & PF_R != 0 {
        permissions = permissions.bitor(MemoryPermissions::READ);
    }
    if flags & PF_W != 0 {
        permissions = permissions.bitor(MemoryPermissions::WRITE);
    }
    if flags & PF_X != 0 {
        permissions = permissions.bitor(MemoryPermissions::EXECUTE);
    }
    permissions
}

pub(crate) fn program_header_error(index: u16, field: ProgramHeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::ProgramHeader {
            index,
            field,
            value,
        },
    )
}
