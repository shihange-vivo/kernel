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

//! Exact segment-permission admission and its interaction with image checks.

use super::fixture::{ElfFixtureBuilder, ProgramHeaderFixture, SliceElfReader};
use crate::{
    error::{ErrorContext, LoadErrorKind, LoadStage, ProgramHeaderField},
    image::ImageLoader,
    memory::{MemoryPermissions, TargetAddress},
    profile::{ElfClass, LoadLimits, LoadProfile, LoadRequest, SegmentPermissionPolicy},
    LoadResult,
};
use alloc::vec::Vec;
use blueos_test_macro::test;
use goblin::elf::{
    header::ET_DYN,
    program_header::{PF_R, PF_W, PF_X, PT_GNU_STACK},
};

const PROFILES: [LoadProfile; 3] = [
    LoadProfile::riscv32(),
    LoadProfile::riscv64(),
    LoadProfile::aarch64(),
];

fn load(vaddr: u64, flags: u32) -> ProgramHeaderFixture {
    ProgramHeaderFixture {
        vaddr: TargetAddress::new(vaddr),
        flags,
        ..ProgramHeaderFixture::load()
    }
}

fn fixture(profile: LoadProfile, entry: u64, headers: &[ProgramHeaderFixture]) -> Vec<u8> {
    let machine = u64::from(profile.machine()) as u16;
    let mut builder = match profile.class() {
        ElfClass::Elf32 => ElfFixtureBuilder::elf32(machine, ET_DYN),
        ElfClass::Elf64 => ElfFixtureBuilder::elf64(machine, ET_DYN),
    }
    .with_entry(entry);
    for header in headers {
        builder = builder.with_program_header(*header);
    }
    builder.build()
}

fn plan(bytes: &[u8], profile: LoadProfile) -> LoadResult<()> {
    ImageLoader::new(
        SliceElfReader::new(bytes),
        LoadRequest::new(profile, LoadLimits::DEFAULT),
    )
    .admit()?
    .inspect()?
    .plan()
    .map(drop)
}

#[test]
fn segment_permission_whitelists_accept_exact_combinations() {
    let rx = MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE);
    let wx = MemoryPermissions::WRITE.bitor(MemoryPermissions::EXECUTE);
    let custom = SegmentPermissionPolicy::new(&[
        MemoryPermissions::NONE,
        MemoryPermissions::WRITE,
        MemoryPermissions::EXECUTE,
        rx,
        wx,
        wx.bitor(MemoryPermissions::READ),
    ]);
    for base in PROFILES {
        for custom_policy in [false, true] {
            let profile = if custom_policy {
                base.with_segment_permission_policy(custom)
            } else {
                base
            };
            for flags in 0..8 {
                let bytes = fixture(
                    profile,
                    0x1000,
                    &[load(0x1000, PF_R | PF_X), load(0x2000, flags)],
                );
                let accepted = if custom_policy {
                    flags != PF_R && flags != (PF_R | PF_W)
                } else {
                    matches!(flags, PF_R) || flags == (PF_R | PF_W) || flags == (PF_R | PF_X)
                };
                let result = plan(&bytes, profile);
                if accepted {
                    result.unwrap();
                } else {
                    let error = result.unwrap_err();
                    let kind = if flags & (PF_W | PF_X) == (PF_W | PF_X) {
                        LoadErrorKind::PermissionConflict
                    } else {
                        LoadErrorKind::UnsupportedByProfile
                    };
                    assert_eq!(error.kind(), kind);
                    assert_eq!(error.stage(), Some(LoadStage::Inspect));
                    assert!(matches!(error.context(), ErrorContext::ProgramHeader {
                        index: 1, field: ProgramHeaderField::Permissions, value,
                    } if *value == u64::from(flags)));
                }
            }
        }
    }
}

#[test]
fn segment_permission_updates_preserve_other_combinations_and_profiles() {
    let rwx = MemoryPermissions::READ
        .bitor(MemoryPermissions::WRITE)
        .bitor(MemoryPermissions::EXECUTE);
    for base in PROFILES {
        let policy = base.segment_permission_policy().with_permissions(rwx, true);
        let profile = base.with_segment_permission_policy(policy);
        let bytes = fixture(profile, 0x1000, &[load(0x1000, PF_R | PF_W | PF_X)]);
        plan(&bytes, profile).unwrap();
        assert_eq!(
            plan(&bytes, base).unwrap_err().kind(),
            LoadErrorKind::PermissionConflict
        );
        let disabled = profile.with_segment_permission_policy(policy.with_permissions(rwx, false));
        assert_eq!(
            plan(&bytes, disabled).unwrap_err().kind(),
            LoadErrorKind::PermissionConflict
        );
        let bytes = fixture(profile, 0x1000, &[load(0x1000, PF_W | PF_X)]);
        assert_eq!(
            plan(&bytes, profile).unwrap_err().kind(),
            LoadErrorKind::PermissionConflict
        );
    }
}

#[test]
fn permissive_segment_permissions_preserve_layout_and_entry_validation() {
    let rwx = MemoryPermissions::READ
        .bitor(MemoryPermissions::WRITE)
        .bitor(MemoryPermissions::EXECUTE);
    for base in PROFILES {
        let profile = base.with_segment_permission_policy(
            base.segment_permission_policy().with_permissions(rwx, true),
        );
        for (entry, align, data, kind) in [
            (0x1000, 3, 0x2000, LoadErrorKind::InvalidAlignment),
            (0x1000, 4, 0x1080, LoadErrorKind::BadElf),
            (0x1001, 4, 0x2000, LoadErrorKind::InvalidAlignment),
            (0x2000, 4, 0x2000, LoadErrorKind::PermissionConflict),
        ] {
            let bytes = fixture(
                profile,
                entry,
                &[
                    ProgramHeaderFixture {
                        align,
                        ..load(0x1000, PF_R | PF_W | PF_X)
                    },
                    load(data, PF_R | PF_W),
                ],
            );
            let error = plan(&bytes, profile).unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.stage(), Some(LoadStage::Plan));
        }
    }
}

#[test]
fn segment_and_executable_stack_admission_remain_independent() {
    let rwx = MemoryPermissions::READ
        .bitor(MemoryPermissions::WRITE)
        .bitor(MemoryPermissions::EXECUTE);
    for base in PROFILES {
        for (allow_segment, allow_stack, rejected_field) in [
            (true, false, Some(ProgramHeaderField::ExecutableStack)),
            (false, true, Some(ProgramHeaderField::Permissions)),
            (true, true, None),
        ] {
            let profile = base
                .with_segment_permission_policy(
                    base.segment_permission_policy()
                        .with_permissions(rwx, allow_segment),
                )
                .with_program_header_policy(
                    base.program_header_policy()
                        .with_executable_stack(allow_stack),
                );
            let bytes = fixture(
                profile,
                0x1000,
                &[
                    load(0x1000, PF_R | PF_W | PF_X),
                    ProgramHeaderFixture {
                        kind: PT_GNU_STACK,
                        filesz: 0,
                        memsz: 0,
                        flags: PF_R | PF_W | PF_X,
                        ..ProgramHeaderFixture::load()
                    },
                ],
            );
            let result = plan(&bytes, profile);
            if let Some(field) = rejected_field {
                let error = result.unwrap_err();
                assert_eq!(error.stage(), Some(LoadStage::Inspect));
                assert!(matches!(
                    (error.context(), field),
                    (
                        ErrorContext::ProgramHeader {
                            index: 1,
                            field: ProgramHeaderField::ExecutableStack,
                            ..
                        },
                        ProgramHeaderField::ExecutableStack
                    ) | (
                        ErrorContext::ProgramHeader {
                            index: 0,
                            field: ProgramHeaderField::Permissions,
                            ..
                        },
                        ProgramHeaderField::Permissions
                    )
                ));
            } else {
                result.unwrap();
            }
        }
    }
}
