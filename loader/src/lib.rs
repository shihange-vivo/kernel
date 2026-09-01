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
use error::{LoadError, LoadErrorKind};
use goblin::elf::{
    header::{
        EI_CLASS, EI_DATA, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, EM_AARCH64, EM_ARM,
        EM_RISCV, ET_DYN, ET_EXEC,
    },
    Elf,
};
use identity::{ElfClass, ElfData, ElfMachine, ElfType, LoadLimits, LoadProfile, LoadRequest};
use image::ImageLoader;
use memory_mapper::MappingModeKind;
use reader::SliceElfReader;
use relocation::{ArmRelocator, Riscv32Relocator, Riscv64Relocator};

pub use memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion};

pub type Result = core::result::Result<(), &'static str>;

fn build_memory_layout(binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    for ph in &binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                // We're assuming loadable segments are compact.
                mapper
                    .update_start(ph.p_vaddr as usize)
                    .update_end((ph.p_vaddr + ph.p_memsz) as usize);
            }
            _ => continue,
        }
    }
    mapper.set_entry(binary.entry as usize);
    Ok(())
}

fn copy_content_to_memory(buffer: &[u8], binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    // FIXME: We are assuming if filesize < memsize, (memsize -
    // filesize) bits are .bss. I need to read more about ELF spec to
    // find out exceptions. Currently, it just works.
    for ph in &binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                let Some(src) =
                    buffer.get(ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize)
                else {
                    return Err("Invalid indices to the buffer");
                };
                mapper.write_slice_at(ph.p_vaddr as usize, src)?;
            }
            _ => continue,
        }
    }
    Ok(())
}

fn load_dyn_elf(buffer: &[u8], binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    if !mapper.can_load_dynamic_image() {
        return Err("ET_DYN requires Allocated mapping mode");
    }

    let (profile, class, machine) = dynamic_load_profile(binary)?;
    let request = LoadRequest::new(profile, LoadLimits::DEFAULT);
    let decoded = ImageLoader::new(SliceElfReader::new(buffer), request)
        .admit()
        .and_then(|image| image.inspect())
        .and_then(|image| image.plan())
        .and_then(|image| image.allocate(MemoryMapper::new(None)))
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
        .install_dynamic_image(load_bias, runtime_entry)
        .map_err(compatibility_error)?;
    loaded_mapper.real_entry()?;
    *mapper = loaded_mapper;
    Ok(())
}

fn dynamic_load_profile(
    binary: &Elf,
) -> core::result::Result<(LoadProfile, ElfClass, ElfMachine), &'static str> {
    let class = match binary.header.e_ident[EI_CLASS] {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        _ => return Err("Unsupported ELF class"),
    };
    let endian = match binary.header.e_ident[EI_DATA] {
        ELFDATA2LSB => ElfData::Little,
        ELFDATA2MSB => ElfData::Big,
        _ => return Err("Unsupported ELF endian"),
    };
    let machine = match binary.header.e_machine {
        EM_ARM => ElfMachine::Arm,
        EM_RISCV => ElfMachine::Riscv,
        EM_AARCH64 => ElfMachine::Aarch64,
        value => ElfMachine::Ohter(value),
    };
    Ok((
        LoadProfile::new(class, endian, machine, ElfType::Dyn),
        class,
        machine,
    ))
}

fn compatibility_error(error: LoadError) -> &'static str {
    match error.stage() {
        Some(error::LoadStage::Admit) => "Unable to admit dynamic ELF",
        Some(error::LoadStage::Inspect) => "Unable to inspect dynamic ELF",
        Some(error::LoadStage::Plan) => "Unable to plan dynamic ELF",
        Some(error::LoadStage::Allocate) => "Unable to allocate dynamic ELF",
        Some(error::LoadStage::Map) => "Unable to map dynamic ELF",
        Some(error::LoadStage::Decode) => "Unable to decode dynamic ELF",
        Some(error::LoadStage::Relocate) => "Unable to relocate dynamic ELF",
        Some(error::LoadStage::Cache) => "Unable to synchronize dynamic ELF",
        Some(error::LoadStage::Seal) => "Unable to seal dynamic ELF",
        None => "Unable to load dynamic ELF",
    }
}

fn load_exec_elf(buffer: &[u8], binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    if mapper.mode_kind() != MappingModeKind::Fixed {
        return Err("ET_EXEC requires Fixed mapping mode");
    }
    build_memory_layout(binary, mapper)?;
    copy_content_to_memory(buffer, binary, mapper)?;
    mapper.real_entry()?;
    Ok(())
}

// FIXME: We should use lseek to parse ELF files to achieve low footprint.
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> Result {
    let binary = Elf::parse(buffer).map_err(|_| "Unable to parse the buffer")?;
    match binary.header.e_type {
        ET_DYN => load_dyn_elf(buffer, &binary, mapper),
        ET_EXEC => load_exec_elf(buffer, &binary, mapper),
        _ => Err("Unsupported ELF type"),
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
