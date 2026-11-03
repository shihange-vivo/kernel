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
use goblin::elf::dynamic::{
    DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1, DT_JMPREL, DT_NEEDED,
    DT_NULL, DT_PLTREL, DT_PLTRELSZ, DT_SONAME, DT_STRSZ, DT_STRTAB,
};

use crate::{
    elf::DynamicSegmentInfo,
    error::{oom, LoadErrorKind},
    image::map::{decode_dynamic_entry, dynamic_error, unsupported_dynamic},
    profile::{supports_dynamic_tag, ElfClass, ElfData, LoadLimits},
    reader::ElfReader,
    LoadError, LoadResult,
};

/// summary of the dynamic features an image requests.
///
/// Produced from file-backed `PT_DYNAMIC` before image allocation or writes.
/// It records raw `DT_NEEDED`/`DT_SONAME` string-table offsets rather than
/// resolving them: full dynstr decoding is deferred to , but the presence of
/// every policy-gated feature is decided here so an unsupported image never
/// reaches image allocation. The `DT_STRTAB`/`DT_STRSZ` pair is also recorded:
/// the read-only dependency scanner resolves the offsets from the file with
/// the same summary instead of re-decoding the whole table.
pub(crate) struct DynamicFeatureSummary {
    pie: bool,
    needed: Vec<u64>,
    soname: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<u64>,
}

impl DynamicFeatureSummary {
    pub(crate) const fn empty() -> Self {
        Self {
            pie: false,
            needed: Vec::new(),
            soname: None,
            strtab: None,
            strsz: None,
        }
    }

    pub(crate) const fn is_pie(&self) -> bool {
        self.pie
    }

    #[inline]
    pub(crate) fn needed(&self) -> &[u64] {
        &self.needed
    }

    #[inline]
    pub(crate) const fn soname(&self) -> Option<u64> {
        self.soname
    }

    /// The `DT_STRTAB` vaddr, when the table declares one.
    #[inline]
    pub(crate) const fn strtab(&self) -> Option<u64> {
        self.strtab
    }

    /// The `DT_STRSZ` byte length, when the table declares one.
    #[inline]
    pub(crate) const fn strsz(&self) -> Option<u64> {
        self.strsz
    }
}

/// Scan the file-backed `PT_DYNAMIC` and return a feature summary,
/// rejecting any tag the policy does not permit.
///
/// This runs before image allocation, so unsupported features (`RPATH/RUNPATH`,
/// symbol versioning, unknown tags, …) fail with
/// zero image allocations and zero writes.
pub(crate) fn validate_dynamic_features<R: ElfReader>(
    reader: &R,
    dynamic: &DynamicSegmentInfo,
    class: ElfClass,
    endian: ElfData,
    limits: &LoadLimits,
) -> LoadResult<DynamicFeatureSummary> {
    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    let file_range = dynamic.file_range();
    if file_range.is_empty() || !file_range.len().is_multiple_of(entry_size) {
        return Err(dynamic_error(DT_NULL, file_range.len()));
    }
    if file_range.len() > dynamic.memory_size() {
        return Err(dynamic_error(DT_NULL, file_range.len()));
    }

    let entry_count = file_range.len() / entry_size;
    let mut needed = Vec::new();
    let mut soname = None;
    let mut strtab = None;
    let mut strsz = None;
    let mut has_plt_relocations = false;
    let mut bind_now = false;
    let mut pie = false;

    let mut raw = [0; 16];
    let mut terminated = false;
    for index in 0..entry_count {
        limits.check_dynamic_entry_count(index + 1)?;
        let offset = file_range
            .offset()
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::IntegerOverflow,
                    crate::error::ErrorContext::DynamicTag {
                        tag: DT_NULL,
                        value: index,
                    },
                )
            })?)
            .ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::IntegerOverflow,
                    crate::error::ErrorContext::DynamicTag {
                        tag: DT_NULL,
                        value: index,
                    },
                )
            })?;
        reader.read_exact_at(offset, &mut raw[..entry_size as usize])?;
        let (tag, value) = decode_dynamic_entry(&raw[..entry_size as usize], class, endian)?;
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        if !supports_dynamic_tag(tag, value) {
            return Err(unsupported_dynamic(tag, value));
        }
        match tag {
            DT_NEEDED => {
                // The entry budget was checked before this read. Padding
                // after DT_NULL and other tags must not drive reservations.
                needed.try_reserve(1).map_err(|_| oom())?;
                needed.push(value);
            }
            DT_SONAME => {
                if soname.replace(value).is_some() {
                    return Err(dynamic_error(DT_SONAME, value));
                }
            }
            DT_STRTAB => {
                if strtab.replace(value).is_some() {
                    return Err(dynamic_error(DT_STRTAB, value));
                }
            }
            DT_STRSZ => {
                if strsz.replace(value).is_some() {
                    return Err(dynamic_error(DT_STRSZ, value));
                }
            }
            DT_PLTRELSZ | DT_PLTREL | DT_JMPREL => has_plt_relocations = true,
            DT_BIND_NOW => bind_now = true,
            DT_FLAGS if value & DF_BIND_NOW != 0 => bind_now = true,
            DT_FLAGS_1 => {
                bind_now |= value & DF_1_NOW != 0;
                pie |= value & DF_1_PIE != 0;
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(dynamic_error(DT_NULL, file_range.len()));
    }

    // A shared object may omit `DT_SONAME`: when present the offset is
    // bounds-checked against `DT_STRSZ` later during metadata decoding.
    // Distinguishing two
    // SONAME-less files is the resolver's job — by identity and path — not
    // this stage's.
    if has_plt_relocations && !bind_now {
        return Err(unsupported_dynamic(DT_JMPREL, 0));
    }

    Ok(DynamicFeatureSummary {
        pie,
        needed,
        soname,
        strtab,
        strsz,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::{ErrorContext, LimitKind},
        memory::address::{FileRange, TargetAddress},
    };
    use blueos_test_macro::test;
    use core::cell::Cell;
    use goblin::elf::dynamic::DT_RPATH;

    const PADDED_TABLE_BYTES: u64 = 64 * 1024 * 1024;

    /// A sparse table: absent prefix entries are DT_NULL, without allocating
    /// the potentially large padding declared by the file-backed range.
    struct TableReader<'a> {
        entries: &'a [(u64, u64)],
        class: ElfClass,
        endian: ElfData,
        bytes: u64,
        reads: Cell<usize>,
    }

    impl TableReader<'_> {
        fn entry_size(&self) -> u64 {
            match self.class {
                ElfClass::Elf32 => 8,
                ElfClass::Elf64 => 16,
            }
        }

        fn summary(&self, maximum: u64) -> LoadResult<DynamicFeatureSummary> {
            let dynamic = DynamicSegmentInfo::new(
                FileRange::new(0, self.bytes),
                TargetAddress::new(0x1000),
                self.bytes,
            );
            let limits = LoadLimits::new(
                PADDED_TABLE_BYTES,
                128,
                32,
                64 * 1024 * 1024,
                1024 * 1024 * 1024,
                maximum,
                1024 * 1024,
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                256,
                256,
            );
            validate_dynamic_features(self, &dynamic, self.class, self.endian, &limits)
        }
    }

    fn encode_word(value: u64, dst: &mut [u8], endian: ElfData) {
        match (dst.len(), endian) {
            (4, ElfData::Little) => {
                dst.copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
            }
            (4, ElfData::Big) => {
                dst.copy_from_slice(&u32::try_from(value).unwrap().to_be_bytes());
            }
            (8, ElfData::Little) => dst.copy_from_slice(&value.to_le_bytes()),
            (8, ElfData::Big) => dst.copy_from_slice(&value.to_be_bytes()),
            _ => panic!("unexpected dynamic word size"),
        }
    }

    impl ElfReader for TableReader<'_> {
        fn len(&self) -> LoadResult<u64> {
            Ok(self.bytes)
        }

        fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
            let entry_size = self.entry_size();
            assert_eq!(dst.len() as u64, entry_size);
            assert!(offset.is_multiple_of(entry_size));
            assert!(offset
                .checked_add(entry_size)
                .is_some_and(|end| end <= self.bytes));
            self.reads.set(self.reads.get().saturating_add(1));
            let index = usize::try_from(offset / entry_size).unwrap();
            let (tag, value) = self.entries.get(index).copied().unwrap_or((DT_NULL, 0));
            let (tag_bytes, value_bytes) = dst.split_at_mut(dst.len() / 2);
            encode_word(tag, tag_bytes, self.endian);
            encode_word(value, value_bytes, self.endian);
            Ok(())
        }
    }

    #[test]
    fn dynamic_early_null_bounds_storage_despite_large_padding() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                let reader = TableReader {
                    entries: &[],
                    class,
                    endian,
                    bytes: PADDED_TABLE_BYTES,
                    reads: Cell::new(0),
                };
                let summary = reader.summary(1).expect("first entry is DT_NULL");
                assert!(summary.needed().is_empty());
                assert!(summary.needed.capacity() <= 1);
                assert_eq!(reader.reads.get(), 1);
            }
        }
    }

    #[test]
    fn dynamic_entry_limit_precedes_reads_and_dependency_allocation() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                for maximum in 0..=2 {
                    let reader = TableReader {
                        entries: &[(DT_NEEDED, 1), (DT_NEEDED, 2)],
                        class,
                        endian,
                        bytes: PADDED_TABLE_BYTES,
                        reads: Cell::new(0),
                    };
                    let error = reader.summary(maximum).err().expect("entry limit");
                    assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
                    assert!(matches!(
                        error.context(),
                        ErrorContext::Limit {
                            resource: LimitKind::DynamicEntryCount,
                            actual,
                            maximum: reported_maximum,
                        } if *actual == maximum.saturating_add(1)
                            && *reported_maximum == maximum
                    ));
                    assert_eq!(reader.reads.get() as u64, maximum);
                }
            }
        }
    }

    #[test]
    fn dynamic_needed_offsets_survive_bounded_growth_and_padding() {
        let entries = [
            (DT_STRTAB, 0x1000),
            (DT_STRSZ, 16),
            (DT_SONAME, 1),
            (DT_FLAGS, DF_BIND_NOW),
            (DT_FLAGS_1, DF_1_PIE),
            (DT_NEEDED, 3),
            (DT_NEEDED, 7),
        ];
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                let reader = TableReader {
                    entries: &entries,
                    class,
                    endian,
                    bytes: PADDED_TABLE_BYTES,
                    reads: Cell::new(0),
                };
                let summary = reader.summary(8).expect("DT_NULL is within the limit");
                assert_eq!(summary.needed(), &[3, 7]);
                assert!(summary.needed.capacity() <= 8);
                assert_eq!(summary.soname(), Some(1));
                assert!(summary.is_pie());
                assert_eq!(reader.reads.get(), 8);
            }
        }
    }

    #[test]
    fn dynamic_rejects_unterminated_tables_within_the_entry_limit() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                let mut reader = TableReader {
                    entries: &[(DT_NEEDED, 1), (DT_NEEDED, 2)],
                    class,
                    endian,
                    bytes: 0,
                    reads: Cell::new(0),
                };
                reader.bytes = reader.entry_size().checked_mul(2).unwrap();
                let error = reader.summary(2).err().expect("missing DT_NULL");
                assert_eq!(error.kind(), LoadErrorKind::BadElf);
                assert_eq!(reader.reads.get(), 2);
            }
        }
    }

    #[test]
    fn dynamic_unsupported_tag_is_reported_before_dependency_storage() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [ElfData::Little, ElfData::Big] {
                let reader = TableReader {
                    entries: &[(DT_RPATH, 0)],
                    class,
                    endian,
                    bytes: PADDED_TABLE_BYTES,
                    reads: Cell::new(0),
                };
                let error = reader.summary(1).err().expect("unsupported dynamic tag");
                assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
                assert_eq!(reader.reads.get(), 1);
            }
        }
    }
}
