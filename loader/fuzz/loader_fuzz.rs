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

#![cfg_attr(fuzzing, no_main)]

use std::borrow::Cow;

use blueos_loader::{
    prepare_image, AllocationId, AllocationLease, AllocationOwnership, AllocationRequest,
    ArchRelocator, ArchitectureCodeCache, ArmRelocator, ArtifactProfile, ArtifactRequest,
    CacheRequirements, ElfClass, ErrorContext, ExecutionScope, ExpectedElfType, ImageAllocation,
    ImageMemory, ImageProtectionMemory, LoadError, LoadErrorKind, LoadLimits, LoadResult,
    LoadStage, MemoryError, MemoryPermissions, MemoryResult, MutationProgress,
    PreparedProtectionPlan, ProtectionCapabilities, ProtectionLevel, Riscv32Relocator,
    Riscv64Relocator, SliceElfReader, TargetAddr, TargetLocation,
};

const CORPUS: &[&[u8]] = &[
    include_bytes!("corpus/empty.hex"),
    include_bytes!("corpus/truncated_magic.hex"),
    include_bytes!("corpus/valid_arm32.hex"),
    include_bytes!("corpus/valid_riscv64.hex"),
    include_bytes!("corpus/valid_riscv64_rela.hex"),
];

#[derive(Default)]
struct VirtualMemory {
    allocation: Option<ImageAllocation>,
    bytes: Vec<u8>,
}

impl ImageMemory for VirtualMemory {
    fn allocate_image(&mut self, request: &AllocationRequest) -> LoadResult<AllocationLease> {
        let target_base = TargetAddr::new(0x4000_0000)
            .align_up(request.align())
            .map_err(|error| error.at(LoadStage::Allocate))?;
        let len = usize::try_from(request.size()).map_err(|_| fuzz_oom())?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| fuzz_oom())?;
        bytes.resize(len, 0xa5);
        let allocation = ImageAllocation::new(
            AllocationId::new(1),
            target_base,
            request.size(),
            request.align(),
            AllocationOwnership::Owned,
        );
        self.bytes = bytes;
        self.allocation = Some(allocation);
        // SAFETY: this harness creates one live allocation and never clones its
        // lease; abort is the only terminal path used by `prepare_image`.
        Ok(unsafe { AllocationLease::from_allocation(allocation) })
    }

    fn abort_image(&mut self, _lease: AllocationLease, _progress: MutationProgress) {
        self.allocation = None;
        self.bytes.clear();
    }

    fn release_committed(&mut self, _lease: AllocationLease) {
        self.allocation = None;
        self.bytes.clear();
    }

    fn validate_access(
        &self,
        location: TargetLocation,
        len: u64,
        _permissions: MemoryPermissions,
    ) -> MemoryResult<()> {
        let Some(allocation) = self.allocation else {
            return Err(fuzz_memory_error(location, len));
        };
        let end = location
            .offset()
            .checked_add(len)
            .ok_or_else(|| fuzz_memory_error(location, len))?;
        if location.allocation() == allocation.id() && end <= allocation.len() {
            Ok(())
        } else {
            Err(fuzz_memory_error(location, len))
        }
    }

    fn write(&mut self, location: TargetLocation, data: &[u8]) -> MemoryResult<()> {
        self.validate_access(location, data.len() as u64, MemoryPermissions::WRITE)?;
        let start = location.offset() as usize;
        self.bytes[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn zero(&mut self, location: TargetLocation, len: u64) -> MemoryResult<()> {
        self.validate_access(location, len, MemoryPermissions::WRITE)?;
        let start = location.offset() as usize;
        self.bytes[start..start + len as usize].fill(0);
        Ok(())
    }

    fn read(&self, location: TargetLocation, dst: &mut [u8]) -> MemoryResult<()> {
        self.validate_access(location, dst.len() as u64, MemoryPermissions::READ)?;
        let start = location.offset() as usize;
        dst.copy_from_slice(&self.bytes[start..start + dst.len()]);
        Ok(())
    }

    fn protect(
        &mut self,
        location: TargetLocation,
        len: u64,
        permissions: MemoryPermissions,
    ) -> MemoryResult<ProtectionLevel> {
        self.validate_access(location, len, permissions)?;
        Ok(ProtectionLevel::LogicalOnly)
    }
}

impl ImageProtectionMemory for VirtualMemory {
    fn protection_capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities::new(1, usize::MAX)
    }

    fn validate_protection_aliases(
        &self,
        _allocation: &ImageAllocation,
        _prepared: &PreparedProtectionPlan,
    ) -> LoadResult<()> {
        Ok(())
    }
}

fn fuzz_memory_error(location: TargetLocation, len: u64) -> MemoryError {
    MemoryError::new(
        LoadErrorKind::Backend,
        ErrorContext::MemoryAccess {
            allocation: location.allocation(),
            offset: location.offset(),
            len,
        },
    )
}

fn fuzz_oom() -> LoadError {
    LoadError::new(
        LoadStage::Allocate,
        LoadErrorKind::OutOfMemory,
        ErrorContext::None,
    )
}

fn exercise_profile<A: ArchRelocator + ?Sized>(
    bytes: &[u8],
    profile: ArtifactProfile,
    relocator: &A,
) -> LoadResult<()> {
    let request = ArtifactRequest::new(ExpectedElfType::Dyn, profile, LoadLimits::phase0_mcu());
    let mut memory = VirtualMemory::default();
    let mut cache = ArchitectureCodeCache::new(CacheRequirements::new(
        ExecutionScope::CurrentExecutionContext,
    ));
    let result = prepare_image(
        SliceElfReader::new(bytes),
        request,
        &mut memory,
        &mut cache,
        relocator,
    );
    result.map(|_| ())
}

fn exercise_one_input(input: &[u8]) {
    let bytes = decode_hex_corpus(input);
    let _ = exercise_profile(
        &bytes,
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf64),
        &Riscv64Relocator,
    );
    let _ = exercise_profile(
        &bytes,
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf32),
        &Riscv32Relocator,
    );
    let _ = exercise_profile(&bytes, ArtifactProfile::arm_thumb_v7m_soft(), &ArmRelocator);
}

fn decode_hex_corpus(input: &[u8]) -> Cow<'_, [u8]> {
    let input = input.strip_suffix(b"\n").unwrap_or(input);
    let input = input.strip_suffix(b"\r").unwrap_or(input);
    if input.len() % 2 != 0 || !input.iter().all(u8::is_ascii_hexdigit) {
        return Cow::Borrowed(input);
    }

    let mut decoded = Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let high = hex_digit(pair[0]);
        let low = hex_digit(pair[1]);
        decoded.push((high << 4) | low);
    }
    Cow::Owned(decoded)
}

fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

#[cfg(not(fuzzing))]
fn main() {
    for seed in CORPUS {
        exercise_one_input(seed);
        let decoded = decode_hex_corpus(seed);
        for &len in &[0, 1, 4, 16, 52, 64, decoded.len()] {
            exercise_one_input(&decoded[..len.min(decoded.len())]);
        }
        for &offset in &[0, 1, 4, 5, 16, 20, 24, 32, 40, 48, 56, 64] {
            if offset < decoded.len() {
                let mut mutated = decoded.to_vec();
                mutated[offset] ^= 0xff;
                exercise_one_input(&mutated);
            }
        }
    }

    exercise_profile(
        &decode_hex_corpus(CORPUS[2]),
        ArtifactProfile::arm_thumb_v7m_soft(),
        &ArmRelocator,
    )
    .unwrap();
    exercise_profile(
        &decode_hex_corpus(CORPUS[3]),
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf64),
        &Riscv64Relocator,
    )
    .unwrap();
    exercise_profile(
        &decode_hex_corpus(CORPUS[4]),
        ArtifactProfile::riscv_compressed_soft(ElfClass::Elf64),
        &Riscv64Relocator,
    )
    .unwrap();
}

#[cfg(fuzzing)]
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if data.is_null() && size != 0 {
        return 0;
    }
    let input = if size == 0 {
        &[]
    } else {
        // SAFETY: libFuzzer supplies `size` readable bytes for every non-empty
        // invocation; the null guard above also protects manual ABI callers.
        unsafe { std::slice::from_raw_parts(data, size) }
    };
    exercise_one_input(input);
    0
}
