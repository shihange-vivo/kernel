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

//! Dynamic application loading: platform adapters that bind the loader's
//! neutral contracts (`ElfReader`, `ArtifactResolver`, `ImageMemory`, …) to
//! the kernel's VFS, memory and cache services.
//!
//! Phase 1 is delivered slice-by-slice. C23-b lands the read-only
//! [`adapters::vfs_reader::VfsElfReader`] and the fixed
//! [`adapters::system_paths::SystemLibraryPaths`] catalog; C23-c adds the
//! [`adapters::flat_memory::FlatImageMemory`] shared-flat backend. C24 adds the
//! [`registry::SystemDsoRegistry`] permit/lease/generation state machine that
//! turns a relocated system image into a shareable Ready instance and hands
//! back either a load permit or an import lease (§13). The
//! [`ArtifactResolver`] adaptation and the manager/group orchestration follow
//! in C24/C25.

/// The board policy's dynamic-application profile (§9.1): the single place
/// where the board ABI decides which loader profile a bare (non-package)
/// application links with.
#[cfg(target_board = "qemu_mps2_an385")]
pub fn board_dynamic_profile() -> blueos_loader::LoadProfile {
    blueos_loader::LoadProfile::arm_thumb_soft_float(blueos_loader::ElfType::Dyn)
}

#[cfg(target_board = "qemu_mps3_an547")]
pub fn board_dynamic_profile() -> blueos_loader::LoadProfile {
    blueos_loader::LoadProfile::arm_thumb_hard_float(blueos_loader::ElfType::Dyn)
}

pub mod adapters;
pub mod event_queue;
pub mod group;
pub mod loader;
pub mod manager;
#[cfg(boot_dynamic_seed)]
pub mod package;
pub mod publication;
pub mod reaper;
pub mod registry;
#[cfg(boot_dynamic_seed)]
pub mod seed;
pub mod service;
pub mod start_storage;
