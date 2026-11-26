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

//! Load one self-contained ELF and own its finalized image.

use super::LoadRequest;
use crate::{
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::ImageLoader,
    memory::{ProtectionLevel, TargetAddress},
    CodeCache, ElfReader, ImageAllocator, ImageMapping, InterpreterImage, LifecyclePlan, LoadError,
    LoadResult, ProgramHeaderTable,
};

/// Retains image backing and its validated runtime addresses.
///
/// Move this owner into the application or runtime that retains the image.
/// Before dropping it, the host must finish execution, any desired finalization
/// and all other uses of its code or data. Drop only releases the mapping;
/// it does not run lifecycle callbacks or stop executing threads.
#[must_use = "retain the loaded image for as long as its code or data is in use"]
pub struct LoadedImage<A: ImageMapping> {
    program_headers: Option<ProgramHeaderTable>,
    allocation: A,
    entry: Option<TargetAddress>,
    lifecycle: LifecyclePlan,
}

impl<A: ImageMapping> LoadedImage<A> {
    pub(crate) const fn new(
        allocation: A,
        entry: Option<TargetAddress>,
        program_headers: Option<ProgramHeaderTable>,
        lifecycle: LifecyclePlan,
    ) -> Self {
        Self {
            program_headers,
            allocation,
            entry,
            lifecycle,
        }
    }

    /// Backend-owned mapping, retained until this image is dropped.
    pub const fn allocation(&self) -> &A {
        &self.allocation
    }

    /// Runtime entry address. Executable requests always return Some, even
    /// when the runtime address is zero; a shared object may have no entry.
    pub const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    /// Complete readable in-image table, if the ELF maps it through PT_LOAD.
    /// None does not invalidate loading; hosts requiring AT_PHDR must reject
    /// startup or supply an appropriate mapping rather than invent an address.
    pub const fn program_headers(&self) -> Option<ProgramHeaderTable> {
        self.program_headers
    }

    /// Ordered runtime callback addresses, not yet executed by the loader.
    pub const fn lifecycle(&self) -> &LifecyclePlan {
        &self.lifecycle
    }

    /// Protection actually provided by the backend for this mapping.
    pub fn protection_level(&self) -> ProtectionLevel {
        self.allocation.protection_level()
    }
}

/// Load and finalize one self-contained ELF without executing its code.
///
/// Accepts fixed-address ET_EXEC and relocatable ET_DYN images admitted by
/// `request.profile()`. DT_NEEDED dependencies are rejected before allocation;
/// relocations must be NONE or supported explicit-addend RELATIVE records.
/// `SharedObject` permits a self-contained library without an entry, but does
/// not enable dependency loading or symbol binding.
///
/// The reader is consumed and released once copying completes, or on failure.
/// The host supplies its concrete reader, which may also be borrowed. The mapping must
/// outlive every use of the returned entry and lifecycle addresses. Loading
/// failures and discarding the result release backing through the mapping's
/// Drop implementation; they do not execute finalizers or restore old bytes.
///
/// The host supplies initial read/write backing, permission changes and code
/// cache synchronization. Successful loading does not initialize the application
/// runtime or authorize calls from a context incompatible with that backend.
///
/// Stack usage depends on concrete reader, allocator and mapping types as well
/// as backend calls; keep large backend state behind small owning or borrowed
/// handles.
pub fn load_elf<R, M, C>(
    reader: R,
    request: LoadRequest,
    allocator: M,
    cache: &mut C,
) -> LoadResult<LoadedImage<M::Allocation>>
where
    R: ElfReader,
    M: ImageAllocator,
    C: CodeCache + ?Sized,
{
    // Forward Result between stages instead of unwrapping each large stage into
    // an intermediate ControlFlow payload. This keeps the pipeline's stack small.
    ImageLoader::new(reader, request)
        .prepare_layout()
        .and_then(|image| {
            if let Some(dynamic) = image.dynamic() {
                request
                    .profile()
                    .check_standalone_dynamic(dynamic)
                    .map_err(|error| error.at_stage(LoadStage::Plan))?;
            }
            image.allocate(allocator)
        })
        .and_then(|image| image.map())
        .and_then(|image| image.decode())
        .and_then(|image| image.relocate())
        .and_then(|image| image.seal(cache))
}

/// Map a PIE or its ELF interpreter for startup by an external runtime.
/// The host maps the interpreter named by PT_INTERP and supplies the initial
/// stack. The interpreter handles dynamic metadata, TLS and RELRO sealing
/// after relocation.
pub fn map_elf_for_interpreter<R, M, C>(
    reader: R,
    request: LoadRequest,
    page_size: u64,
    allocator: M,
    cache: &mut C,
) -> LoadResult<InterpreterImage<M::Allocation>>
where
    R: ElfReader,
    M: ImageAllocator,
    C: CodeCache + ?Sized,
{
    use crate::elf::ElfType;
    use goblin::elf::program_header::{PT_GNU_PROPERTY, PT_INTERP, PT_NOTE, PT_TLS};

    let invalid = || LoadError::new(LoadErrorKind::BadElf, ErrorContext::None);
    if !page_size.is_power_of_two() {
        return Err(invalid());
    }
    let request = LoadRequest::new(
        request.profile().with_additional_program_headers(&[
            PT_INTERP,
            PT_TLS,
            PT_NOTE,
            PT_GNU_PROPERTY,
        ]),
        *request.limits(),
    );
    ImageLoader::new(reader, request)
        .admit()
        .and_then(|image| {
            if image.header().r#type() != ElfType::Dyn {
                return Err(invalid().at_stage(LoadStage::Admit));
            }
            image.inspect()
        })
        .and_then(|image| image.plan_for_interpreter(page_size))
        .and_then(|(image, interpreter)| {
            image
                .allocate(allocator)
                .and_then(|image| image.map())
                .and_then(|image| image.hand_off(interpreter, cache))
        })
}
