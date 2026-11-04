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

use crate::image::{
    symbol_count_from_hash, DependencyName, ImageLifecycleMetadata, ProgramHeaderGeometry,
    RuntimeImageMetadata, RuntimeImageState, SymbolTable,
};

use alloc::vec::Vec;
use goblin::elf::dynamic::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT,
    DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTREL, DT_PLTRELSZ,
    DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT,
    DT_RELSZ, DT_SONAME, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB,
};

use crate::{
    elf::{read_u32, read_u64, DynamicSegmentInfo, LoadSegmentInfo},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::{
        decode::{
            DecodedImage, DynamicTags, RelocationAddend, RelocationRecord, RelocationTableKind,
            RelocationTableTags,
        },
        inspect::StackKind,
    },
    memory::{
        address::{FileRange, TargetAddress, TargetRange},
        AllocationOffset, ImageLoadTransaction, ImageMemory,
    },
    profile::{supports_dynamic_tag, ElfClass, ElfData, LoadRequest},
    LoadError, LoadResult,
};

pub(crate) struct LoadedRegion {
    vaddr_range: TargetRange,
    runtime_range: TargetRange,
    file_range: FileRange,
    allocation_offset: AllocationOffset,
}

impl LoadedRegion {
    #[inline]
    pub const fn new(
        vaddr_range: TargetRange,
        runtime_range: TargetRange,
        file_range: FileRange,
        allocation_offset: AllocationOffset,
    ) -> Self {
        Self {
            vaddr_range,
            runtime_range,
            file_range,
            allocation_offset,
        }
    }

    #[inline]
    pub const fn vaddr_range(&self) -> TargetRange {
        self.vaddr_range
    }

    #[inline]
    pub const fn runtime_range(&self) -> TargetRange {
        self.runtime_range
    }

    #[inline]
    pub const fn file_range(&self) -> FileRange {
        self.file_range
    }

    #[inline]
    pub const fn allocation_offset(&self) -> AllocationOffset {
        self.allocation_offset
    }
}

#[must_use = "dropping a mapped image aborts its allocation"]
pub(crate) struct MappedImage<M: ImageMemory> {
    transaction: ImageLoadTransaction<M>,
    load_bias: TargetAddress,
    request: LoadRequest,
    entry_vaddr: TargetAddress,
    load_segments: Vec<LoadSegmentInfo>,
    regions: Vec<LoadedRegion>,
    dynamic: Option<DynamicSegmentInfo>,
    relro: Option<TargetRange>,
    stack: StackKind,
    phdr_geometry: ProgramHeaderGeometry,
}

impl<M: ImageMemory> MappedImage<M> {
    #[inline]
    pub fn new(
        transaction: ImageLoadTransaction<M>,
        load_bias: TargetAddress,
        request: LoadRequest,
        entry_vaddr: TargetAddress,
        load_segments: Vec<LoadSegmentInfo>,
        regions: Vec<LoadedRegion>,
        dynamic: Option<DynamicSegmentInfo>,
        relro: Option<TargetRange>,
        stack: StackKind,
        phdr_geometry: ProgramHeaderGeometry,
    ) -> Self {
        Self {
            transaction,
            load_bias,
            request,
            entry_vaddr,
            load_segments,
            regions,
            dynamic,
            relro,
            stack,
            phdr_geometry,
        }
    }

    fn locate_vaddr_at(&self, vaddr: TargetAddress, len: u64) -> LoadResult<AllocationOffset> {
        let region = self.locate_region(vaddr, len)?;
        let offset = vaddr.checked_sub(region.vaddr_range().start())?;
        region.allocation_offset().checked_add(offset)
    }

    fn locate_region(&self, vaddr: TargetAddress, len: u64) -> LoadResult<&LoadedRegion> {
        self.regions
            .iter()
            .find(|region| region.vaddr_range().contains_span(vaddr, len))
            .ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange {
                        start: vaddr,
                        len,
                        align: 0,
                    },
                )
            })
    }

    fn locate_file_backed_dynamic(
        &self,
        dynamic: &DynamicSegmentInfo,
    ) -> LoadResult<AllocationOffset> {
        for region in self.regions.iter() {
            if !region
                .vaddr_range()
                .contains_span(dynamic.vaddr(), dynamic.file_range().len())
            {
                continue;
            }
            let offset = dynamic.vaddr().checked_sub(region.vaddr_range().start())?;
            let expected_file_offset = region
                .file_range()
                .offset()
                .checked_add(offset)
                .ok_or_else(|| dynamic_error(DT_NULL, dynamic.file_range().offset()))?;
            // The dynamic bytes must lie wholly within this region's
            // *file-backed* range: a PT_DYNAMIC reaching into BSS is malformed.
            let file_end = offset
                .checked_add(dynamic.file_range().len())
                .filter(|end| *end <= region.file_range().len());
            if file_end.is_none() {
                continue;
            }
            if expected_file_offset == dynamic.file_range().offset() {
                return self.locate_vaddr_at(dynamic.vaddr(), dynamic.file_range().len());
            }
        }
        Err(LoadError::new(
            LoadErrorKind::OutOfBounds,
            ErrorContext::TargetRange {
                start: dynamic.vaddr(),
                len: dynamic.file_range().len(),
                align: 0,
            },
        ))
    }

    fn decode_dynamic_tags(&self, dynamic: &DynamicSegmentInfo) -> LoadResult<DynamicTags> {
        let entry_size = dynamic_entry_size(self.request.profile().class());

        if dynamic.file_range().is_empty() || !dynamic.file_range().len().is_multiple_of(entry_size)
        {
            return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
        }
        if dynamic.file_range().len() > dynamic.memory_size() {
            return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
        }
        let offset = self.locate_file_backed_dynamic(dynamic)?;
        self.transaction
            .validate_range(offset, dynamic.file_range().len())?;

        let limits = self.request.limits();
        let entry_count = dynamic.file_range().len() / entry_size;
        let mut tags = DynamicTags::default();
        let mut raw = [0; 16];
        let mut terminated = false;
        for index in 0..entry_count {
            limits.check_dynamic_entry_count(index + 1)?;
            let current =
                offset.checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                    LoadError::new(
                        LoadErrorKind::IntegerOverflow,
                        ErrorContext::DynamicTag {
                            tag: DT_NULL,
                            value: index,
                        },
                    )
                })?)?;
            self.transaction
                .read(current, &mut raw[..entry_size as usize])?;
            let (tag, value) = decode_dynamic_entry(
                &raw[..entry_size as usize],
                self.request.profile().class(),
                self.request.profile().endian(),
            )?;
            if tag == DT_NULL {
                terminated = true;
                break;
            }
            accept_dynamic_tag(&mut tags, tag, value)?;
        }
        if !terminated {
            return Err(dynamic_error(DT_NULL, dynamic.file_range().len()));
        }
        Ok(tags)
    }

    fn decode_relocation_table(
        &self,
        tags: &RelocationTableTags,
        kind: RelocationTableKind,
        records: &mut Vec<RelocationRecord>,
    ) -> LoadResult<()> {
        let absent =
            tags.address().is_none() && tags.byte_len().is_none() && tags.entry_size().is_none();
        if absent {
            return Ok(());
        }
        let tag = match kind {
            RelocationTableKind::Rel => DT_REL,
            RelocationTableKind::Rela => DT_RELA,
        };
        let (Some(address), Some(byte_len), Some(entry_size)) =
            (tags.address(), tags.byte_len(), tags.entry_size())
        else {
            return Err(dynamic_error(tag, 0));
        };
        let expected_entry_size = relocation_entry_size(self.request.profile().class(), kind);
        if entry_size != expected_entry_size || byte_len % entry_size != 0 {
            return Err(dynamic_error(tag, entry_size));
        }
        let count = byte_len / entry_size;
        let existing = u64::try_from(records.len()).map_err(|_| dynamic_error(tag, count))?;
        let total = existing
            .checked_add(count)
            .ok_or_else(|| dynamic_error(tag, count))?;
        self.request.limits().check_relocation_count(total)?;
        let count_usize = usize::try_from(count).map_err(|_| dynamic_error(tag, count))?;
        records.try_reserve_exact(count_usize).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag { tag, value: count },
            )
        })?;
        let table_vaddr = TargetAddress::new(address);
        if byte_len != 0 {
            let offset = self.locate_vaddr_at(table_vaddr, byte_len)?;
            self.transaction.validate_range(offset, byte_len)?;
            let mut raw = [0; 24];
            for index in 0..count {
                let entry_offset = offset.checked_add(index * entry_size)?;
                self.transaction
                    .read(entry_offset, &mut raw[..entry_size as usize])?;
                let record = decode_relocation_entry(
                    &raw[..entry_size as usize],
                    self.request.profile().class(),
                    self.request.profile().endian(),
                    kind,
                )?;
                records.push(record);
            }
        }
        Ok(())
    }

    /// Decode the `DT_JMPREL`/`DT_PLTREL` PLT relocation table, if present.
    ///
    /// JMPREL has no per-table `*ENT` tag: its entry geometry is derived from
    /// `DT_PLTREL` (`DT_REL` or `DT_RELA`), which must be present and
    /// self-consistent whenever JMPREL is.
    fn decode_plt_relocations(
        &self,
        tags: &DynamicTags,
        records: &mut Vec<RelocationRecord>,
    ) -> LoadResult<()> {
        let jmp_absent = tags.jmp_rel().address().is_none()
            && tags.jmp_rel().byte_len().is_none()
            && tags.jmp_rel().entry_size().is_none();
        match (jmp_absent, tags.pltrel()) {
            (true, None) => return Ok(()),
            (true, Some(_)) => return Err(dynamic_error(DT_JMPREL, 0)),
            (false, None) => return Err(dynamic_error(DT_PLTREL, 0)),
            (false, Some(_)) => {}
        }
        let entry_kind = match tags.pltrel() {
            Some(DT_REL) => RelocationTableKind::Rel,
            Some(DT_RELA) => RelocationTableKind::Rela,
            _ => return Err(dynamic_error(DT_PLTREL, tags.pltrel().unwrap_or(0))),
        };
        let entry_size = relocation_entry_size(self.request.profile().class(), entry_kind);
        let synthesized = RelocationTableTags::with_entry_size(tags.jmp_rel(), entry_size);
        self.decode_relocation_table(&synthesized, entry_kind, records)
    }

    pub(crate) fn decode(self) -> LoadResult<DecodedImage<M>> {
        let program_headers = self
            .phdr_geometry
            .resolve(self.load_bias)
            .map_err(|error| error.at_stage(LoadStage::Decode))?;
        let mut metadata = RuntimeImageMetadata::empty(program_headers);
        if let Some(dynamic) = &self.dynamic {
            let tags = self
                .decode_dynamic_tags(dynamic)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            let mut records = Vec::new();
            self.decode_relocation_table(tags.rel(), RelocationTableKind::Rel, &mut records)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            self.decode_relocation_table(tags.rela(), RelocationTableKind::Rela, &mut records)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            self.decode_plt_relocations(&tags, &mut records)?;
            let relocations = records;
            let (symbols, needed, soname) = self
                .decode_symbols_and_dependencies(&tags)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            let lifecycle = self
                .decode_lifecycle(&tags)
                .map_err(|error| error.at_stage(LoadStage::Decode))?;
            metadata = RuntimeImageMetadata::new(
                needed,
                soname,
                symbols,
                relocations,
                lifecycle,
                program_headers,
            );
        }
        self.request
            .limits()
            .check_runtime_metadata_bytes(metadata.metadata_bytes())
            .map_err(|error| error.at_stage(LoadStage::Decode))?;

        Ok(DecodedImage {
            transaction: self.transaction,
            runtime: RuntimeImageState::new(
                self.regions,
                self.load_segments,
                metadata,
                self.load_bias,
                self.entry_vaddr,
                self.relro,
                self.stack,
            ),
        })
    }

    /// Decode `.dynstr`, `.dynsym`, and the hash table(s) into an
    /// owned, validated [`SymbolTable`], and resolve the raw `DT_NEEDED`/
    /// `DT_SONAME` offsets into owned [`DependencyName`]s against the same
    /// `.dynstr`. The symbol count is proven from a SysV `DT_HASH` or
    /// GNU `DT_GNU_HASH` table — never from section headers.
    fn decode_symbols_and_dependencies(
        &self,
        tags: &DynamicTags,
    ) -> LoadResult<(SymbolTable, Vec<DependencyName>, Option<DependencyName>)> {
        let class = self.request.profile().class();
        let endian = self.request.profile().endian();
        let thumb = self.request.profile().entry_mode().is_thumb();
        let max_name_len = self.request.limits().max_symbol_name_len();
        let expected_syment: u64 = match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };

        let any_symbol_tag = tags.symtab().is_some()
            || tags.syment().is_some()
            || tags.strtab().is_some()
            || tags.strsz().is_some()
            || tags.hash().is_some()
            || tags.gnu_hash().is_some()
            || !tags.needed().is_empty()
            || tags.soname().is_some();
        if !any_symbol_tag {
            return Ok((SymbolTable::empty(), Vec::new(), None));
        }

        // `DT_STRTAB`/`DT_STRSZ` and `DT_SYMTAB`/`DT_SYMENT` are paired tags.
        let (strtab, strsz) = match (tags.strtab(), tags.strsz()) {
            (Some(strtab), Some(strsz)) => (strtab, strsz),
            _ => return Err(dynamic_error(DT_STRTAB, 0)),
        };
        let (symtab, syment) = match (tags.symtab(), tags.syment()) {
            (Some(symtab), Some(syment)) => (symtab, syment),
            _ => return Err(dynamic_error(DT_SYMTAB, 0)),
        };
        if syment != expected_syment {
            return Err(dynamic_error(DT_SYMENT, syment));
        }

        self.request.limits().check_string_table_bytes(strsz)?;
        let dynstr = self.read_table_bytes(strtab, strsz, DT_STRTAB)?;

        // Resolve dependency names against the same `.dynstr` before it is
        // moved into the symbol table. `DT_NEEDED` keeps encounter order.
        let needed = self.decode_dependency_names(tags.needed(), &dynstr, DT_NEEDED)?;
        let soname = match tags.soname() {
            Some(offset) => Some(self.decode_dependency_name(offset, &dynstr, DT_SONAME)?),
            None => None,
        };

        let sysv_bytes = match tags.hash() {
            Some(hash_vaddr) => {
                // A SysV table is self-describing: the header carries the
                // bucket/chain counts that bound the whole read.
                let mut header = [0; 8];
                let offset = self.locate_vaddr_at(TargetAddress::new(hash_vaddr), 8)?;
                self.transaction.read(offset, &mut header)?;
                let nbucket = read_u32(&header, 0, endian)?;
                let nchain = read_u32(&header, 4, endian)?;
                let total = 8u64
                    .checked_add(4u64 * (u64::from(nbucket) + u64::from(nchain)))
                    .ok_or_else(|| dynamic_error(DT_HASH, 0))?;
                Some(self.read_table_bytes(hash_vaddr, total, DT_HASH)?)
            }
            None => None,
        };

        let gnu_bytes = match tags.gnu_hash() {
            Some(gnu_vaddr) => Some(
                self.read_gnu_hash_bytes(
                    gnu_vaddr,
                    class,
                    endian,
                    expected_syment,
                    sysv_bytes
                        .as_deref()
                        .map(|bytes| read_u32(bytes, 4, endian))
                        .transpose()?,
                )?,
            ),
            None => None,
        };

        let symbol_count =
            symbol_count_from_hash(class, endian, gnu_bytes.as_deref(), sysv_bytes.as_deref())?;

        let symtab_len = u64::from(symbol_count)
            .checked_mul(syment)
            .ok_or_else(|| dynamic_error(DT_SYMTAB, 0))?;
        // All symbol entries are charged against the total metadata budget
        // *before* parsing, so a malformed table with a huge proven count can
        // never reserve memory past the limit.
        self.request
            .limits()
            .check_runtime_metadata_bytes(symtab_len)?;
        let symtab_bytes = self.read_table_bytes(symtab, symtab_len, DT_SYMTAB)?;

        let symbols = SymbolTable::decode(
            &symtab_bytes,
            dynstr,
            class,
            endian,
            self.load_bias,
            &self.load_segments,
            thumb,
            max_name_len,
            gnu_bytes,
            sysv_bytes,
        )?;
        Ok((symbols, needed, soname))
    }

    /// Decode a list of `DT_NEEDED` offsets into owned, validated
    /// [`DependencyName`]s, bounded by `max_dependency_name_len`.
    fn decode_dependency_names(
        &self,
        offsets: &[u64],
        dynstr: &[u8],
        tag: u64,
    ) -> LoadResult<Vec<DependencyName>> {
        let mut names = Vec::new();
        names.try_reserve_exact(offsets.len()).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag {
                    tag,
                    value: offsets.len() as u64,
                },
            )
        })?;
        for &offset in offsets {
            names.push(self.decode_dependency_name(offset, dynstr, tag)?);
        }
        Ok(names)
    }

    /// Decode one `DT_NEEDED`/`DT_SONAME` offset into an owned
    /// [`DependencyName`], bounded by `max_dependency_name_len`.
    fn decode_dependency_name(
        &self,
        offset: u64,
        dynstr: &[u8],
        tag: u64,
    ) -> LoadResult<DependencyName> {
        decode_dependency_name_at(
            offset,
            dynstr,
            tag,
            self.request.limits().max_dependency_name_len(),
        )
    }

    /// Save the lifecycle targets and array ranges without fixing
    /// the array contents into function addresses. The array entry
    /// words are re-read after relocation by the lifecycle plan builder.
    fn decode_lifecycle(&self, tags: &DynamicTags) -> LoadResult<ImageLifecycleMetadata> {
        let word_size = match self.request.profile().class() {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        let init = tags.init().map(TargetAddress::new);
        let fini = tags.fini().map(TargetAddress::new);
        let preinit_array = self.array_range(
            tags.preinit_array(),
            tags.preinit_arraysz(),
            word_size,
            DT_PREINIT_ARRAY,
        )?;
        let init_array = self.array_range(
            tags.init_array(),
            tags.init_arraysz(),
            word_size,
            DT_INIT_ARRAY,
        )?;
        let fini_array = self.array_range(
            tags.fini_array(),
            tags.fini_arraysz(),
            word_size,
            DT_FINI_ARRAY,
        )?;
        Ok(ImageLifecycleMetadata::new(
            init,
            fini,
            preinit_array,
            init_array,
            fini_array,
        ))
    }

    /// Pair an init/fini array address with its size into a validated
    /// [`TargetRange`]. Both tags must be present together, the size must be a
    /// whole number of target words, and the range end must not overflow.
    fn array_range(
        &self,
        address: Option<u64>,
        size: Option<u64>,
        word_size: u64,
        tag: u64,
    ) -> LoadResult<Option<TargetRange>> {
        match (address, size) {
            (None, None) => Ok(None),
            (Some(address), Some(size)) => {
                if size % word_size != 0 {
                    return Err(dynamic_error(tag, size));
                }
                let range = TargetRange::new(TargetAddress::new(address), size);
                range.end().map_err(|_| dynamic_error(tag, size))?;
                Ok(Some(range))
            }
            _ => Err(dynamic_error(tag, 0)),
        }
    }

    /// Read `len` bytes at `vaddr` through the owner-bound transaction into an
    /// owned, bounded buffer. A zero-length read yields an empty box without
    /// touching the allocation.
    fn read_table_bytes(&self, vaddr: u64, len: u64, tag: u64) -> LoadResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let offset = self.locate_vaddr_at(TargetAddress::new(vaddr), len)?;
        self.transaction.validate_range(offset, len)?;
        let len_usize = usize::try_from(len).map_err(|_| dynamic_error(tag, len))?;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(len_usize).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag { tag, value: len },
            )
        })?;
        buffer.resize(len_usize, 0);
        self.transaction.read(offset, &mut buffer)?;
        Ok(buffer)
    }

    /// Read exactly the reachable GNU hash extent without relying on section
    /// adjacency. When SysV hash is also present its `nchain` supplies the
    /// symbol count; otherwise the chain beginning at the greatest bucket is
    /// scanned to its bounded terminator.
    fn read_gnu_hash_bytes(
        &self,
        vaddr: u64,
        class: ElfClass,
        endian: ElfData,
        syment: u64,
        known_symbol_count: Option<u32>,
    ) -> LoadResult<Vec<u8>> {
        let header = self.read_table_bytes(vaddr, 16, DT_GNU_HASH)?;
        let nbuckets = read_u32(&header, 0, endian)?;
        let symndx = read_u32(&header, 4, endian)?;
        let maskwords = read_u32(&header, 8, endian)?;
        let shift2 = read_u32(&header, 12, endian)?;
        if nbuckets == 0 || maskwords == 0 || !maskwords.is_power_of_two() || shift2 >= u32::BITS {
            return Err(dynamic_error(DT_GNU_HASH, vaddr));
        }

        let word_size = match class {
            ElfClass::Elf32 => 4_u64,
            ElfClass::Elf64 => 8_u64,
        };
        let head_len = 16_u64
            .checked_add(
                u64::from(maskwords)
                    .checked_mul(word_size)
                    .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?,
            )
            .and_then(|value| value.checked_add(u64::from(nbuckets) * 4))
            .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;

        if let Some(symbol_count) = known_symbol_count {
            let chain_count = symbol_count
                .checked_sub(symndx)
                .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
            let total = head_len
                .checked_add(u64::from(chain_count) * 4)
                .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
            self.request.limits().check_runtime_metadata_bytes(total)?;
            return self.read_table_bytes(vaddr, total, DT_GNU_HASH);
        }

        self.request
            .limits()
            .check_runtime_metadata_bytes(head_len)?;
        let head = self.read_table_bytes(vaddr, head_len, DT_GNU_HASH)?;
        let bucket_base = usize::try_from(
            16_u64
                .checked_add(u64::from(maskwords) * word_size)
                .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?,
        )
        .map_err(|_| dynamic_error(DT_GNU_HASH, vaddr))?;
        let mut greatest_bucket = 0_u32;
        for index in 0..nbuckets as usize {
            let bucket = read_u32(&head, bucket_base + index * 4, endian)?;
            if bucket != 0 && bucket < symndx {
                return Err(dynamic_error(DT_GNU_HASH, u64::from(bucket)));
            }
            greatest_bucket = greatest_bucket.max(bucket);
        }
        if greatest_bucket == 0 {
            return Ok(head);
        }

        let max_symbols = self.request.limits().max_runtime_metadata_bytes() / syment;
        if u64::from(greatest_bucket) >= max_symbols {
            return Err(dynamic_error(DT_GNU_HASH, u64::from(greatest_bucket)));
        }
        let mut chain_index = greatest_bucket - symndx;
        let maximum_chain_count = max_symbols
            .checked_sub(u64::from(symndx))
            .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
        // The final table must fit one mapped region. Cache that mapping and
        // cap every scan read by both its extent and the metadata budget.
        let table_vaddr = TargetAddress::new(vaddr);
        let region = self.locate_region(table_vaddr, head_len)?;
        let region_delta = table_vaddr.checked_sub(region.vaddr_range().start())?;
        let table_offset = region.allocation_offset().checked_add(region_delta)?;
        let region_bytes = region
            .vaddr_range()
            .len()
            .checked_sub(region_delta)
            .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
        let maximum_table_bytes =
            region_bytes.min(self.request.limits().max_runtime_metadata_bytes());
        let mut buffer = [0u8; 256];
        loop {
            if u64::from(chain_index) >= maximum_chain_count {
                return Err(dynamic_error(DT_GNU_HASH, u64::from(chain_index)));
            }
            let prefix_len = u64::from(chain_index)
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(head_len))
                .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
            let words = (maximum_table_bytes.saturating_sub(prefix_len) / 4)
                .min(maximum_chain_count.saturating_sub(u64::from(chain_index)))
                .min((buffer.len() / 4) as u64);
            if words == 0 {
                let total = prefix_len
                    .checked_add(4)
                    .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
                self.request.limits().check_runtime_metadata_bytes(total)?;
                return Err(LoadError::new(
                    LoadErrorKind::OutOfBounds,
                    ErrorContext::TargetRange {
                        start: table_vaddr,
                        len: total,
                        align: 0,
                    },
                ));
            }
            let len = usize::try_from(
                words
                    .checked_mul(4)
                    .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?,
            )
            .map_err(|_| dynamic_error(DT_GNU_HASH, vaddr))?;
            let offset = table_offset.checked_add(prefix_len)?;
            self.transaction.validate_range(offset, len as u64)?;
            self.transaction.read(offset, &mut buffer[..len])?;
            for word in buffer[..len].chunks_exact(4) {
                if read_u32(word, 0, endian)? & 1 != 0 {
                    let chain_count = chain_index
                        .checked_add(1)
                        .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
                    let total = head_len
                        .checked_add(u64::from(chain_count) * 4)
                        .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
                    self.request.limits().check_runtime_metadata_bytes(total)?;
                    return self.read_table_bytes(vaddr, total, DT_GNU_HASH);
                }
                chain_index = chain_index
                    .checked_add(1)
                    .ok_or_else(|| dynamic_error(DT_GNU_HASH, vaddr))?;
            }
        }
    }
}

const fn dynamic_entry_size(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    }
}

const fn relocation_entry_size(class: ElfClass, kind: RelocationTableKind) -> u64 {
    match (class, kind) {
        (ElfClass::Elf32, RelocationTableKind::Rel) => 8,
        (ElfClass::Elf32, RelocationTableKind::Rela) => 12,
        (ElfClass::Elf64, RelocationTableKind::Rel) => 16,
        (ElfClass::Elf64, RelocationTableKind::Rela) => 24,
    }
}

pub(crate) fn decode_dynamic_entry(
    bytes: &[u8],
    class: ElfClass,
    endian: ElfData,
) -> LoadResult<(u64, u64)> {
    Ok(match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(bytes, 0, endian)?),
            u64::from(read_u32(bytes, 4, endian)?),
        ),
        ElfClass::Elf64 => (read_u64(bytes, 0, endian)?, read_u64(bytes, 8, endian)?),
    })
}

fn set_once(slot: &mut Option<u64>, tag: u64, value: u64) -> LoadResult<()> {
    if slot.replace(value).is_some() {
        Err(dynamic_error(tag, value))
    } else {
        Ok(())
    }
}

fn decode_relocation_entry(
    bytes: &[u8],
    class: ElfClass,
    endian: ElfData,
    kind: RelocationTableKind,
) -> LoadResult<RelocationRecord> {
    let (offset, info, addend) = match (class, kind) {
        (ElfClass::Elf32, RelocationTableKind::Rel) => (
            u64::from(read_u32(bytes, 0, endian)?),
            u64::from(read_u32(bytes, 4, endian)?),
            RelocationAddend::Implicit,
        ),
        (ElfClass::Elf32, RelocationTableKind::Rela) => (
            u64::from(read_u32(bytes, 0, endian)?),
            u64::from(read_u32(bytes, 4, endian)?),
            RelocationAddend::Explicit(i64::from(read_u32(bytes, 8, endian)? as i32)),
        ),
        (ElfClass::Elf64, RelocationTableKind::Rel) => (
            read_u64(bytes, 0, endian)?,
            read_u64(bytes, 8, endian)?,
            RelocationAddend::Implicit,
        ),
        (ElfClass::Elf64, RelocationTableKind::Rela) => (
            read_u64(bytes, 0, endian)?,
            read_u64(bytes, 8, endian)?,
            RelocationAddend::Explicit(read_u64(bytes, 16, endian)? as i64),
        ),
    };
    let (raw_type, symbol_index) = match class {
        ElfClass::Elf32 => ((info & 0xff) as u32, (info >> 8) as u32),
        ElfClass::Elf64 => (info as u32, (info >> 32) as u32),
    };
    Ok(RelocationRecord::new(
        TargetAddress::new(offset),
        raw_type,
        symbol_index,
        addend,
    ))
}

fn accept_dynamic_tag(tags: &mut DynamicTags, tag: u64, value: u64) -> LoadResult<()> {
    if !supports_dynamic_tag(tag, value) {
        return Err(unsupported_dynamic(tag, value));
    }
    match tag {
        DT_REL => set_once(tags.rel_mut().address_mut(), tag, value),
        DT_RELSZ => set_once(tags.rel_mut().byte_len_mut(), tag, value),
        DT_RELENT => set_once(tags.rel_mut().entry_size_mut(), tag, value),
        DT_RELA => set_once(tags.rela_mut().address_mut(), tag, value),
        DT_RELASZ => set_once(tags.rela_mut().byte_len_mut(), tag, value),
        DT_RELAENT => set_once(tags.rela_mut().entry_size_mut(), tag, value),
        DT_JMPREL => set_once(tags.jmp_rel_mut().address_mut(), tag, value),
        DT_PLTRELSZ => set_once(tags.jmp_rel_mut().byte_len_mut(), tag, value),
        DT_PLTREL => set_once(tags.pltrel_mut(), tag, value),
        DT_SYMTAB => set_once(tags.symtab_mut(), tag, value),
        DT_SYMENT => set_once(tags.syment_mut(), tag, value),
        DT_STRTAB => set_once(tags.strtab_mut(), tag, value),
        DT_STRSZ => set_once(tags.strsz_mut(), tag, value),
        DT_HASH => set_once(tags.hash_mut(), tag, value),
        DT_GNU_HASH => set_once(tags.gnu_hash_mut(), tag, value),
        DT_NEEDED => tags.push_needed(tag, value),
        DT_SONAME => set_once(tags.soname_mut(), tag, value),
        DT_FLAGS => set_once(tags.flags_mut(), tag, value),
        DT_FLAGS_1 => set_once(tags.flags_1_mut(), tag, value),
        DT_INIT => set_once(tags.init_mut(), tag, value),
        DT_FINI => set_once(tags.fini_mut(), tag, value),
        DT_PREINIT_ARRAY => set_once(tags.preinit_array_mut(), tag, value),
        DT_PREINIT_ARRAYSZ => set_once(tags.preinit_arraysz_mut(), tag, value),
        DT_INIT_ARRAY => set_once(tags.init_array_mut(), tag, value),
        DT_INIT_ARRAYSZ => set_once(tags.init_arraysz_mut(), tag, value),
        DT_FINI_ARRAY => set_once(tags.fini_array_mut(), tag, value),
        DT_FINI_ARRAYSZ => set_once(tags.fini_arraysz_mut(), tag, value),
        _ => Ok(()),
    }
}

pub(crate) fn dynamic_error(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag { tag, value },
    )
}

/// Decode one `DT_NEEDED`/`DT_SONAME` string-table offset into an owned
/// [`DependencyName`], bounded by `max_len`.
///
/// Shared by the map stage and the read-only dependency scanner so both
/// always resolve offsets with the same NUL-scan and length rules.
pub(crate) fn decode_dependency_name_at(
    offset: u64,
    dynstr: &[u8],
    tag: u64,
    max_len: u32,
) -> LoadResult<DependencyName> {
    let start = usize::try_from(offset).map_err(|_| dynamic_error(tag, offset))?;
    let tail = dynstr
        .get(start..)
        .ok_or_else(|| dynamic_error(tag, offset))?;
    let scan = core::cmp::min((max_len as usize).saturating_add(1), tail.len());
    let nul = tail[..scan]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| dynamic_error(tag, offset))?;
    if nul == 0 {
        return Err(dynamic_error(tag, offset));
    }
    DependencyName::from_terminated(&tail[..nul + 1]).map_err(|_| dynamic_error(tag, offset))
}

pub(crate) fn unsupported_dynamic(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::UnsupportedByProfile,
        ErrorContext::DynamicTag { tag, value },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::{
            AllocationLease, AllocationRequest, ImageAllocation, ImageLayout, MemoryMapper,
            MutationProgress, Placement,
        },
        profile::{LoadLimits, LoadProfile},
        ExecutionDomainId,
    };
    use alloc::rc::Rc;
    use blueos_test_macro::test;
    use core::cell::{Cell, RefCell};

    #[derive(Default)]
    struct ReadState {
        calls: RefCell<Vec<(u64, usize)>>,
        fail_at: Cell<Option<u64>>,
        aborts: Cell<usize>,
    }

    #[must_use = "keep the test memory alive through its image transaction"]
    struct ReadCountingMemory {
        mapper: MemoryMapper,
        state: Rc<ReadState>,
    }

    impl ImageMemory for ReadCountingMemory {
        fn execution_domain(&self) -> ExecutionDomainId {
            self.mapper.execution_domain()
        }
        fn prepare_image(&mut self, layout: &ImageLayout) -> LoadResult<AllocationLease> {
            self.mapper.prepare_image(layout)
        }
        fn abort_image(&mut self, lease: AllocationLease, progress: MutationProgress) {
            self.state
                .aborts
                .set(self.state.aborts.get().saturating_add(1));
            self.mapper.abort_image(lease, progress);
        }
        fn release_committed(&mut self, lease: AllocationLease) {
            self.mapper.release_committed(lease);
        }
        fn validate_range(
            &self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            len: u64,
        ) -> LoadResult<()> {
            self.mapper.validate_range(allocation, offset, len)
        }
        fn read(
            &self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            dst: &mut [u8],
        ) -> LoadResult<()> {
            self.state
                .calls
                .borrow_mut()
                .push((offset.value(), dst.len()));
            if self.state.fail_at.get() == Some(offset.value()) {
                return Err(LoadError::new(LoadErrorKind::Io, ErrorContext::None));
            }
            self.mapper.read(allocation, offset, dst)
        }
        fn write(
            &mut self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            bytes: &[u8],
        ) -> LoadResult<()> {
            self.mapper.write(allocation, offset, bytes)
        }
        fn zero(
            &mut self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            len: u64,
        ) -> LoadResult<()> {
            self.mapper.zero(allocation, offset, len)
        }
    }

    fn hash_image(
        bytes: &[u8],
        spans: &[(u64, u64)],
        metadata_limit: u64,
    ) -> (MappedImage<ReadCountingMemory>, Rc<ReadState>) {
        let state = Rc::new(ReadState::default());
        let mut memory = ReadCountingMemory {
            mapper: MemoryMapper::new(None),
            state: Rc::clone(&state),
        };
        let lease = memory
            .prepare_image(&crate::tests::fixture::full_image_layout(
                AllocationRequest::new(Placement::Anywhere, bytes.len() as u64, 1),
            ))
            .unwrap();
        let allocation = *lease.allocation();
        memory
            .write(&allocation, AllocationOffset::new(0), bytes)
            .unwrap();
        let regions = spans
            .iter()
            .map(|&(offset, len)| {
                LoadedRegion::new(
                    TargetRange::new(TargetAddress::new(0x1000).checked_add(offset).unwrap(), len),
                    TargetRange::new(allocation.base().checked_add(offset).unwrap(), len),
                    FileRange::new(offset, len),
                    AllocationOffset::new(offset),
                )
            })
            .collect();
        let limits = LoadLimits::new(
            64 * 1024 * 1024,
            128,
            32,
            64 * 1024 * 1024,
            1024 * 1024 * 1024,
            1024,
            1024 * 1024,
            metadata_limit,
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            256,
            256,
        );
        let image = MappedImage::new(
            ImageLoadTransaction::new(memory, lease),
            allocation.base(),
            LoadRequest::new(LoadProfile::riscv64(), limits),
            TargetAddress::new(0),
            Vec::new(),
            regions,
            None,
            None,
            StackKind::NotDeclared,
            ProgramHeaderGeometry::new(0, 0, None),
        );
        (image, state)
    }

    fn gnu_table(
        class: ElfClass,
        endian: ElfData,
        symndx: u32,
        buckets: &[u32],
        chains: &[u32],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let append = |bytes: &mut Vec<u8>, word: u32| {
            bytes.extend_from_slice(&match endian {
                ElfData::Little => word.to_le_bytes(),
                ElfData::Big => word.to_be_bytes(),
            });
        };
        for word in [u32::try_from(buckets.len()).unwrap(), symndx, 1, 5] {
            append(&mut bytes, word);
        }
        bytes.resize(
            match class {
                ElfClass::Elf32 => 20,
                ElfClass::Elf64 => 24,
            },
            0xff,
        );
        for &word in buckets.iter().chain(chains) {
            append(&mut bytes, word);
        }
        bytes
    }

    fn symbol_size(class: ElfClass) -> u64 {
        match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        }
    }

    #[test]
    fn gnu_hash_long_chain_uses_bounded_chunk_reads() {
        let mut chains = [0x100; 129];
        chains[128] |= 1;
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                let table = gnu_table(class, endian, 3, &[3], &chains);
                let mut bytes = alloc::vec![0; 13];
                bytes.extend_from_slice(&table);
                let (image, state) = hash_image(&bytes, &[(0, bytes.len() as u64)], 65536);
                let result = image
                    .read_gnu_hash_bytes(0x100d, class, endian, symbol_size(class), None)
                    .unwrap();
                assert_eq!(result, table);
                assert_eq!(state.calls.borrow().len(), 6);
                assert_eq!(
                    state.calls.borrow()[2..5]
                        .iter()
                        .map(|call| call.1)
                        .collect::<Vec<_>>(),
                    [256, 256, 4]
                );
                drop(image);
                assert_eq!(state.aborts.get(), 1);
            }
        }
    }

    #[test]
    fn gnu_hash_chunk_scan_stops_at_the_first_terminator() {
        for count in [1usize, 64, 65, 128, 129] {
            let mut chains = [0x100; 129];
            chains[count - 1] |= 1;
            let mut table = gnu_table(ElfClass::Elf64, ElfData::Little, 1, &[1], &chains);
            // A non-word tail is readable, but must never become a chain word.
            table.extend_from_slice(&[0xfe; 3]);
            let (image, state) = hash_image(&table, &[(0, table.len() as u64)], 65536);
            let result = image
                .read_gnu_hash_bytes(0x1000, ElfClass::Elf64, ElfData::Little, 24, None)
                .unwrap();
            let total = 28usize.checked_add(count.checked_mul(4).unwrap()).unwrap();
            assert_eq!(result, table[..total]);
            assert_eq!(
                symbol_count_from_hash(ElfClass::Elf64, ElfData::Little, Some(&result), None)
                    .unwrap(),
                u32::try_from(count).unwrap().saturating_add(1)
            );
            assert!(state
                .calls
                .borrow()
                .iter()
                .all(
                    |&(offset, len)| offset.checked_add(len as u64).unwrap() <= table.len() as u64
                ));
        }
    }

    #[test]
    fn gnu_hash_chunk_scan_rejects_truncated_or_split_chains() {
        let mut table = gnu_table(ElfClass::Elf64, ElfData::Little, 1, &[1], &[0x100; 65]);
        let end = table.len() as u64;
        for (spans, readable_end) in [
            (alloc::vec![(0, end)], end),
            (alloc::vec![(0, end - 1)], end - 1),
            (alloc::vec![(0, end - 4), (end - 4, 4)], end - 4),
        ] {
            let (image, state) = hash_image(&table, &spans, 65536);
            let error = image
                .read_gnu_hash_bytes(0x1000, ElfClass::Elf64, ElfData::Little, 24, None)
                .unwrap_err();
            assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
            assert!(state
                .calls
                .borrow()
                .iter()
                .all(|&(offset, len)| offset.checked_add(len as u64).unwrap() <= readable_end));
            drop(image);
            assert_eq!(state.aborts.get(), 1);
        }
        // A terminator in a separate adjacent region still cannot prove one
        // contiguous, readable table extent.
        let last_word = table.len().checked_sub(4).unwrap();
        table[last_word] |= 1;
        let (image, state) = hash_image(&table, &[(0, end - 4), (end - 4, 4)], 65536);
        let error = image
            .read_gnu_hash_bytes(0x1000, ElfClass::Elf64, ElfData::Little, 24, None)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
        assert!(state
            .calls
            .borrow()
            .iter()
            .all(|&(offset, len)| offset.checked_add(len as u64).unwrap() <= end - 4));
    }

    #[test]
    fn gnu_hash_chunk_scan_enforces_metadata_and_symbol_limits() {
        let mut buckets = [0; 32];
        buckets[0] = 1;
        for chains in [&[0x101][..], &[0x100, 0x101][..]] {
            let table = gnu_table(ElfClass::Elf64, ElfData::Little, 1, &buckets, chains);
            let limit = 156; // 152-byte header/Bloom/buckets plus one chain word.
            let (image, state) = hash_image(&table, &[(0, table.len() as u64)], limit);
            let result =
                image.read_gnu_hash_bytes(0x1000, ElfClass::Elf64, ElfData::Little, 24, None);
            if chains.len() == 1 {
                assert_eq!(result.unwrap(), table);
            } else {
                assert_eq!(result.unwrap_err().kind(), LoadErrorKind::ResourceLimit);
            }
            assert!(state
                .calls
                .borrow()
                .iter()
                .all(|&(offset, len)| offset.checked_add(len as u64).unwrap() <= limit));
        }
        let table = gnu_table(
            ElfClass::Elf64,
            ElfData::Little,
            1,
            &[1],
            &[0x100, 0x100, 0x101],
        );
        let (image, state) = hash_image(&table, &[(0, table.len() as u64)], 72);
        let error = image
            .read_gnu_hash_bytes(0x1000, ElfClass::Elf64, ElfData::Little, 24, None)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::BadElf);
        assert_eq!(state.calls.borrow().last(), Some(&(28, 8)));
    }

    #[test]
    fn gnu_hash_known_count_reads_the_exact_extent_without_scanning() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            let table = gnu_table(class, ElfData::Little, 3, &[3], &[0x100, 0x100, 0x101]);
            let (image, state) = hash_image(&table, &[(0, table.len() as u64)], table.len() as u64);
            let result = image
                .read_gnu_hash_bytes(0x1000, class, ElfData::Little, symbol_size(class), Some(6))
                .unwrap();
            assert_eq!(result, table);
            assert_eq!(
                state.calls.borrow().as_slice(),
                &[(0, 16), (0, table.len())]
            );
        }
    }

    #[test]
    fn gnu_hash_chunk_read_failure_keeps_rollback_armed() {
        let table = gnu_table(ElfClass::Elf64, ElfData::Little, 1, &[1], &[0x101]);
        let (image, state) = hash_image(&table, &[(0, table.len() as u64)], 65536);
        state.fail_at.set(Some(28));
        let error = image
            .read_gnu_hash_bytes(0x1000, ElfClass::Elf64, ElfData::Little, 24, None)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::Io);
        assert_eq!(state.calls.borrow().len(), 3);
        assert_eq!(state.aborts.get(), 0);
        drop(image);
        assert_eq!(state.aborts.get(), 1);
    }

    #[test]
    fn dependency_name_accepts_maximum_u32_length_limit() {
        for tag in [DT_NEEDED, DT_SONAME] {
            let name = decode_dependency_name_at(1, b"\0libok.so\0next", tag, u32::MAX)
                .expect("a large limit must accept a short terminated name");
            assert_eq!(name.as_bytes(), b"libok.so");
        }
    }

    #[test]
    fn dependency_name_length_limit_excludes_the_terminator() {
        for tag in [DT_NEEDED, DT_SONAME] {
            let dynstr = b"\0libok.so\0next";
            let name = decode_dependency_name_at(1, dynstr, tag, 8)
                .expect("the terminator may immediately follow the maximum name length");
            assert_eq!(name.as_bytes(), b"libok.so");
            for limit in [0, 7] {
                let error = decode_dependency_name_at(1, dynstr, tag, limit)
                    .expect_err("a name longer than the limit must fail");
                assert!(matches!(error.kind(), LoadErrorKind::BadElf));
                assert!(matches!(
                    error.context(),
                    ErrorContext::DynamicTag { tag: actual, value: 1 } if *actual == tag
                ));
            }
        }
    }

    #[test]
    fn maximum_name_limit_still_rejects_invalid_strings_and_offsets() {
        let cases: &[(&[u8], u64)] = &[
            (b"", 0),
            (b"\0", 0),
            (b"libbad.so", 0),
            (b"x\0", 2),
            (b"x\0", 3),
            (b"x\0", u64::MAX),
        ];
        for tag in [DT_NEEDED, DT_SONAME] {
            for &(dynstr, offset) in cases {
                let error = decode_dependency_name_at(offset, dynstr, tag, u32::MAX)
                    .expect_err("a large limit must still enforce string-table validity");
                assert!(matches!(error.kind(), LoadErrorKind::BadElf));
                assert!(matches!(
                    error.context(),
                    ErrorContext::DynamicTag { tag: actual, value }
                        if *actual == tag && *value == offset
                ));
            }
        }
    }
}
