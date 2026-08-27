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
pub use address::{FileRange, RangeError, RangeResult, TargetAddr, TargetRange};
pub use cache::{
    ArchitectureCodeCache, CacheMaintenance, CacheRequirements, CacheSyncOutcome, CodeCache,
    ExecutionScope, PreparedCacheSync,
};
pub use error::{
    ErrorContext, HeaderField, LimitKind, LoadError, LoadErrorKind, LoadResult, LoadStage,
    ProgramHeaderField,
};
pub use identity::{
    AdmittedArtifact, ArtifactProfile, ArtifactRequest, ElfClass, ElfHeaderInfo, Endian, EntryMode,
    ExpectedElfType, HeaderFlagsPolicy, ImageLoader, RelativeValuePolicy,
};
pub use image::{
    AppliedProtection, AppliedProtectionSet, ArtifactFeaturePolicy, DynamicFeatureSummary,
    DynamicSegmentInfo, ImageLayout, ImageLayoutBuilder, LoadSegmentInfo, LoadedRegion,
    MappedImage, MappedState, ParsedImage, Phase0ArtifactPolicy, PlannedArtifact, PreparedImage,
    PreparedProtectionPlan, ProgramFeatureSummary, ProtectionCapabilities, ProtectionLevel,
    ReadyImageCommit, RelocationAddend, RelocationRecord, RuntimeImage, RuntimeImageMetadata,
    RuntimeState, SealPlan, SealRange, SealedState, SegmentLayout, SegmentLocation, StackPolicy,
};
pub use limits::LoadLimits;
pub(crate) use memory::ImageLoadTransaction;
pub use memory::{
    AllocationId, AllocationLease, AllocationOwnership, AllocationRequest, ImageAllocation,
    ImageCommitMemory, ImageMemory, ImageProtectionMemory, MutationProgress, Placement,
    ReservedImage, ReservedState, StagedImage, TargetLocation,
};
pub use memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion};
pub use reader::{ElfReader, SliceElfReader, SourceSnapshot};
pub use relocation::{
    AddendEncoding, ArchRelocator, ArmRelocator, RelocatedImage, RelocatedState, Riscv32Relocator,
    Riscv64Relocator, TargetWord, WordWidth,
};

/// Result type retained by the original `load_elf` compatibility entry point.
pub type CompatibilityResult = core::result::Result<(), &'static str>;

pub fn prepare_image<'m, R, M, C, A, P>(
    reader: R,
    request: ArtifactRequest,
    memory: &'m mut M,
    cache: &mut C,
    policy: &P,
    relocator: &A,
) -> LoadResult<PreparedImage<'m, M>>
where
    R: ElfReader,
    M: ImageProtectionMemory,
    C: CodeCache,
    A: ArchRelocator + ?Sized,
    P: ArtifactFeaturePolicy + ?Sized,
{
    let loader = ImageLoader::new();
    let admitted = loader.admit(reader, request)?;
    let planned = loader.plan_with_policy(admitted, policy)?;
    let reserved = loader.reserve_staged(planned, memory)?;
    let mapped = reserved.copy_and_zero()?;
    let runtime = mapped.decode_runtime(policy)?;
    let relocated = runtime.relocate(relocator)?;
    relocated.seal(cache)
}

pub fn load_image<R, M, C, A, P>(
    reader: R,
    request: ArtifactRequest,
    memory: &mut M,
    cache: &mut C,
    policy: &P,
    relocator: &A,
) -> LoadResult<M::CommitReceipt>
where
    R: ElfReader,
    M: ImageCommitMemory,
    C: CodeCache,
    A: ArchRelocator + ?Sized,
    P: ArtifactFeaturePolicy + ?Sized,
{
    let prepared = prepare_image(reader, request, memory, cache, policy, relocator)?;
    let ready = prepared.prepare_commit()?;
    Ok(ready.commit())
}

#[cfg(target_arch = "riscv64")]
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> CompatibilityResult {
    load_elf_with_relocator(
        buffer,
        mapper,
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf64),
        CacheRequirements::exact(
            ExecutionScope::CurrentExecutionContext,
            CacheMaintenance::InstructionFence,
        ),
        &Riscv64Relocator,
    )
}

#[cfg(target_arch = "riscv32")]
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> CompatibilityResult {
    load_elf_with_relocator(
        buffer,
        mapper,
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf32),
        CacheRequirements::exact(
            ExecutionScope::CurrentExecutionContext,
            CacheMaintenance::InstructionFence,
        ),
        &Riscv32Relocator,
    )
}

#[cfg(target_arch = "arm")]
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> CompatibilityResult {
    load_elf_with_relocator(
        buffer,
        mapper,
        ArtifactProfile::arm_thumb_v7m_soft(),
        CacheRequirements::exact(
            ExecutionScope::CurrentExecutionContext,
            CacheMaintenance::BarrierOnly,
        ),
        &ArmRelocator,
    )
}

/// AArch64 relocation and compatibility execution are deliberately outside
/// the Phase 0 support matrix. The cache primitive remains available to later
/// linkers, but the single-image compatibility loader must fail explicitly.
#[cfg(target_arch = "aarch64")]
pub fn load_elf(_buffer: &[u8], _mapper: &mut MemoryMapper) -> CompatibilityResult {
    Err("AArch64 is not supported by the Phase 0 loader")
}

#[cfg(not(any(
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "arm",
    target_arch = "aarch64"
)))]
pub fn load_elf(_buffer: &[u8], _mapper: &mut MemoryMapper) -> CompatibilityResult {
    Err("Unsupported loader target architecture")
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "arm"))]
fn load_elf_with_relocator<A: ArchRelocator + ?Sized>(
    buffer: &[u8],
    mapper: &mut MemoryMapper,
    profile: ArtifactProfile,
    cache_requirements: CacheRequirements,
    relocator: &A,
) -> CompatibilityResult {
    let request = ArtifactRequest::new(
        mapper.expected_elf_type(),
        profile,
        LoadLimits::phase0_mcu(),
    )
    .with_cache_requirements(cache_requirements);
    let mut cache = ArchitectureCodeCache;
    load_image(
        SliceElfReader::new(buffer),
        request,
        mapper,
        &mut cache,
        &Phase0ArtifactPolicy,
        relocator,
    )
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
