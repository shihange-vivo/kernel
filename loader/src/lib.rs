// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
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

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod address;
mod cache;
mod error;
mod identity;
mod image;
mod limits;
mod memory;
mod memory_mapper;
mod reader;
mod relocation;
pub use address::{FileRange, TargetAddr, TargetRange};
pub use cache::{ArchitectureCodeCache, CodeCache};
pub use error::{
    ErrorContext, HeaderField, LimitKind, LoadError, LoadErrorKind, LoadResult, LoadStage,
    ProgramHeaderField,
};
pub use identity::{
    AdmittedArtifact, ArtifactProfile, ArtifactRequest, ElfClass, ElfHeaderInfo, Endian,
    ExpectedElfType, ImageLoader,
};
pub use image::{
    DynamicSegmentInfo, ImageLayout, ImageLayoutBuilder, LoadSegmentInfo, LoadedRegion,
    MappedImage, ParsedImage, PlannedArtifact, ProtectionLevel, RelocationAddend, RelocationRecord,
    RuntimeFeaturePolicy, RuntimeImage, RuntimeImageMetadata, SealPlan, SealRange, SealedImage,
    SegmentLayout, SegmentLocation, StackPolicy,
};
pub use limits::LoadLimits;
pub use memory::{
    AllocationId, AllocationOwnership, AllocationRequest, ImageAllocation, ImageLoadTransaction,
    ImageMemory, Placement, ReservedImage, TargetLocation,
};
pub use memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion};
pub use reader::{ElfReader, SliceElfReader};
pub use relocation::{
    AddendEncoding, ArchRelocator, ArmRelocator, RelocatedImage, Riscv32Relocator,
    Riscv64Relocator, TargetWord, WordWidth,
};

pub type Result = core::result::Result<(), &'static str>;

pub fn load_image<R, M, C, A>(
    reader: R,
    request: ArtifactRequest,
    memory: &mut M,
    cache: &mut C,
    runtime_policy: RuntimeFeaturePolicy,
    relocator: &A,
) -> LoadResult<SealedImage>
where
    R: ElfReader,
    M: ImageMemory,
    C: CodeCache,
    A: ArchRelocator + ?Sized,
{
    let loader = ImageLoader::new();
    let admitted = loader.admit(reader, request)?;
    let planned = loader.plan(admitted)?;

    let mut transaction = ImageLoadTransaction::new(memory);
    let reserved = loader.reserve(planned, &mut transaction)?;
    let mapped = loader.copy_and_zero(reserved, &mut transaction)?;
    let runtime = mapped.decode_runtime(&mut transaction, runtime_policy)?;
    let relocated = runtime.relocate(&mut transaction, relocator)?;
    let sealed = relocated.seal(&mut transaction, cache)?;
    transaction.commit_for(&sealed)?;
    Ok(sealed)
}

#[cfg(target_arch = "riscv64")]
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> Result {
    load_elf_with_relocator(
        buffer,
        mapper,
        ArtifactProfile::new(
            ElfClass::Elf64,
            Endian::Little,
            goblin::elf::header::EM_RISCV,
        ),
        &Riscv64Relocator,
    )
}

#[cfg(target_arch = "riscv32")]
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> Result {
    load_elf_with_relocator(
        buffer,
        mapper,
        ArtifactProfile::new(
            ElfClass::Elf32,
            Endian::Little,
            goblin::elf::header::EM_RISCV,
        ),
        &Riscv32Relocator,
    )
}

#[cfg(target_arch = "arm")]
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> Result {
    load_elf_with_relocator(
        buffer,
        mapper,
        ArtifactProfile::new(ElfClass::Elf32, Endian::Little, goblin::elf::header::EM_ARM),
        &ArmRelocator,
    )
}

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm")))]
pub fn load_elf(_buffer: &[u8], _mapper: &mut MemoryMapper) -> Result {
    Err("Unsupported loader target architecture")
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
fn load_elf_with_relocator<A: ArchRelocator + ?Sized>(
    buffer: &[u8],
    mapper: &mut MemoryMapper,
    profile: ArtifactProfile,
    relocator: &A,
) -> Result {
    let request = ArtifactRequest::new(mapper.expected_elf_type(), profile, LoadLimits::default());
    let mut cache = ArchitectureCodeCache;
    let sealed = load_image(
        SliceElfReader::new(buffer),
        request,
        mapper,
        &mut cache,
        RuntimeFeaturePolicy::Phase0,
        relocator,
    )
    .map_err(compatibility_error)?;
    mapper
        .install_sealed(&sealed)
        .map_err(compatibility_error)?;
    Ok(())
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
fn compatibility_error(error: LoadError) -> &'static str {
    match error.kind() {
        LoadErrorKind::BadElf => "Invalid ELF image",
        LoadErrorKind::UnsupportedByProfile => "Unsupported ELF feature",
        LoadErrorKind::OutOfMemory => "Unable to allocate ELF image",
        LoadErrorKind::Io => "Unable to read ELF image",
        _ => "Unable to load ELF image",
    }
}

#[cfg(test)]
mod tests;
