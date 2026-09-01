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
#![feature(c_size_t)]
#![feature(let_chains)]

extern crate alloc;

mod address;
mod cache;
mod elf;
mod error;
mod identity;
mod image;
mod memory;
mod memory_mapper;
mod reader;
mod relocation;

use cache::{ArchitectureCodeCache, CacheRequirements};
use goblin::elf::header::{
    EI_CLASS, EI_DATA, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, EM_AARCH64, EM_ARM,
    EM_RISCV,
};
use identity::{ElfClass, ElfData, ElfMachine, ElfType, LoadLimits, LoadProfile, LoadRequest};
use image::{read_u16, ImageLoader};
use memory_mapper::MappingMode;
use reader::SliceElfReader;
use relocation::{ArmRelocator, Riscv32Relocator, Riscv64Relocator};

pub use error::{ErrorContext, LoadError, LoadErrorKind, LoadResult};
pub use memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion};
pub use reader::ElfReader;

pub type Result = core::result::Result<(), &'static str>;

/// Bytes needed to peek at EI_CLASS, EI_DATA and e_machine before the
/// pipeline takes over (e_machine ends at offset 20).
const PROFILE_PEEK_LEN: u64 = 20;

fn peek_profile(
    reader: &dyn ElfReader,
    expected_type: ElfType,
) -> core::result::Result<LoadProfile, &'static str> {
    let mut peek = [0; PROFILE_PEEK_LEN as usize];
    reader
        .read_exact_at(0, &mut peek)
        .map_err(|_| "Unable to read the ELF header prefix")?;
    let class = match peek[EI_CLASS] {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        _ => return Err("Unsupported ELF class"),
    };
    let endian = match peek[EI_DATA] {
        ELFDATA2LSB => ElfData::Little,
        ELFDATA2MSB => ElfData::Big,
        _ => return Err("Unsupported ELF endian"),
    };
    let machine = match read_u16(&peek, 18, endian).map_err(|_| "Unable to read e_machine")? {
        EM_ARM => ElfMachine::Arm,
        EM_RISCV => ElfMachine::Riscv,
        EM_AARCH64 => ElfMachine::Aarch64,
        value => ElfMachine::Ohter(value),
    };
    Ok(LoadProfile::new(class, endian, machine, expected_type))
}

fn expected_type_for(mapper: &MemoryMapper) -> core::result::Result<ElfType, &'static str> {
    match mapper.mapping_mode() {
        MappingMode::Allocated => Ok(ElfType::Dyn),
        MappingMode::Fixed(_) => Ok(ElfType::Exec),
    }
}

fn compatibility_error(error: LoadError) -> &'static str {
    match error.stage() {
        Some(error::LoadStage::Admit) => "Unable to admit ELF image",
        Some(error::LoadStage::Inspect) => "Unable to inspect ELF image",
        Some(error::LoadStage::Plan) => "Unable to plan ELF image",
        Some(error::LoadStage::Allocate) => "Unable to allocate ELF image",
        Some(error::LoadStage::Map) => "Unable to map ELF image",
        Some(error::LoadStage::Decode) => "Unable to decode ELF image",
        Some(error::LoadStage::Relocate) => "Unable to relocate ELF image",
        Some(error::LoadStage::Cache) => "Unable to synchronize ELF image",
        Some(error::LoadStage::Seal) => "Unable to seal ELF image",
        None => "Unable to load ELF image",
    }
}

/// Load an ELF image from any seek-based reader through the unified
/// ImageLoader pipeline. See [`load_elf`] for the mapper-mode contract.
pub fn load_elf_from_reader<R: ElfReader>(reader: R, mapper: &mut MemoryMapper) -> Result {
    let expected_type = expected_type_for(mapper)?;
    let profile = peek_profile(&reader, expected_type)?;
    let (class, machine) = (profile.class(), profile.machine());
    let request = LoadRequest::new(profile, LoadLimits::DEFAULT);

    let decoded = ImageLoader::new(reader, request)
        .admit()
        .and_then(|image| image.inspect())
        .and_then(|image| image.plan())
        .and_then(|image| image.allocate(core::mem::replace(mapper, MemoryMapper::new(None))))
        .and_then(|image| image.map())
        .and_then(|image| image.decode())
        .map_err(compatibility_error)?;

    let relocated = match (machine, class) {
        (ElfMachine::Arm, ElfClass::Elf32) => decoded.relocation(ArmRelocator),
        (ElfMachine::Riscv, ElfClass::Elf32) => decoded.relocation(Riscv32Relocator),
        (ElfMachine::Riscv, ElfClass::Elf64) => decoded.relocation(Riscv64Relocator),
        _ => Err(LoadError::new(
            LoadErrorKind::UnsupportedByProfile,
            error::ErrorContext::None,
        )),
    }
    .map_err(compatibility_error)?;

    let sealed = relocated
        .cache(ArchitectureCodeCache::new(
            CacheRequirements::CURRENT_EXECUTION_CONTEXT,
        ))
        .and_then(|image| image.seal())
        .map_err(compatibility_error)?;

    let (mut loaded_mapper, load_bias, runtime_entry) = sealed.into_loaded_parts();
    loaded_mapper
        .install_loaded_image(load_bias, runtime_entry)
        .map_err(compatibility_error)?;
    loaded_mapper.real_entry()?;
    *mapper = loaded_mapper;
    Ok(())
}

/// Load an ELF image through the unified ImageLoader pipeline.
///
/// `mapper` decides the image kind: an Allocated mapper accepts movable
/// ET_DYN images on the heap, a Fixed mapper accepts ET_EXEC images inside
/// its static regions. Either way the same parser, copy algorithm and
/// relocation stages run.
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> Result {
    load_elf_from_reader(SliceElfReader::new(buffer), mapper)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
