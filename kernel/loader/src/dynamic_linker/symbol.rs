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

//! Interpret ELF symbol definitions in their mapped images.

use goblin::elf::{
    section_header::{SHN_ABS, SHN_UNDEF},
    sym::{STB_GLOBAL, STB_WEAK, STT_FUNC, STV_DEFAULT, STV_PROTECTED},
};

use crate::{
    elf::{SymbolRecord, SymbolTableReader},
    error::{ErrorContext, LoadErrorKind},
    image::DecodedImage,
    memory::{ImageMapping, MemoryPermissions, TargetAddress, TargetRange},
    ElfReader, LoadError, LoadResult,
};

pub(super) fn read_table<'r, R: ElfReader>(
    image: &DecodedImage<impl ImageMapping>,
    reader: &'r R,
) -> LoadResult<Option<SymbolTableReader<'r, R>>> {
    let Some(dynamic) = image.dynamic() else {
        return Ok(None);
    };
    let profile = image.profile();
    dynamic.symbol_table(reader, image.segments(), profile.class(), profile.endian())
}

/// Find the first definition eligible for binding from another image.
pub(crate) fn lookup_export(
    table: &SymbolTableReader<'_, impl ElfReader>,
    name: &[u8],
    max_name_len: u32,
) -> LoadResult<Option<SymbolRecord>> {
    table.find_by_name(name, max_name_len, is_export)
}

pub(super) fn is_export(symbol: &SymbolRecord) -> bool {
    symbol.name_offset() != 0
        && u32::from(symbol.section_index()) != SHN_UNDEF
        && matches!(symbol.binding(), STB_GLOBAL | STB_WEAK)
        && matches!(symbol.visibility(), STV_DEFAULT | STV_PROTECTED)
}

/// Resolve a record from this image's symbol table. Keep the image alive while
/// using any mapped address. Absolute values carry no backing guarantee.
pub(crate) fn symbol_address(
    image: &DecodedImage<impl ImageMapping>,
    symbol: &SymbolRecord,
) -> LoadResult<Option<TargetAddress>> {
    image.profile().check_symbol(symbol)?;
    let address = TargetAddress::new(symbol.value());
    match u32::from(symbol.section_index()) {
        SHN_UNDEF => return Ok(None),
        SHN_ABS => return Ok(Some(address)),
        _ => {}
    }

    // A zero size gives no extent. The address itself must still be mapped.
    let len = symbol.size().max(1);
    address.checked_add(len)?;
    let context = || ErrorContext::TargetRange {
        start: address,
        len,
        align: 1,
    };
    let segment = image
        .segments()
        .iter()
        .find(|segment| {
            TargetRange::new(segment.vaddr(), segment.memory_size()).contains_span(address, len)
        })
        .ok_or_else(|| LoadError::new(LoadErrorKind::OutOfBounds, context()))?;
    let required = if symbol.kind() == STT_FUNC {
        MemoryPermissions::EXECUTE
    } else {
        MemoryPermissions::READ
    };
    if !segment.permissions().contains(required) {
        return Err(LoadError::new(LoadErrorKind::PermissionConflict, context()));
    }

    let offset = address.checked_sub(image.image_start())?;
    Ok(Some(image.allocation().base().checked_add(offset)?))
}

pub(super) fn contains_executable_span(
    image: &DecodedImage<impl ImageMapping>,
    address: TargetAddress,
    len: u64,
) -> bool {
    let Ok(offset) = address.checked_sub(image.allocation().base()) else {
        return false;
    };
    let Ok(link_address) = image.image_start().checked_add(offset) else {
        return false;
    };
    image.segments().iter().any(|segment| {
        segment.permissions().contains(MemoryPermissions::EXECUTE)
            && TargetRange::new(segment.vaddr(), segment.memory_size())
                .contains_span(link_address, len)
    })
}
