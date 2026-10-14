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

//! Single-image ELF loading stages.
//!
//! `image_loader` defines the staged loader. Follow `admit` → `inspect` → `plan`
//! → `allocate` → `map` → `decode`; `seal` describes final protections. `scan`
//! extracts dependency metadata without mapping and `features` classifies
//! dynamic features. `metadata` and `symbol` describe each decoded image.
//! Multi-image linking is handled by `dynamic_linker`.

mod admit;
mod allocate;
mod decode;
mod features;
mod image_loader;
mod inspect;
mod map;
mod metadata;
mod plan;
pub mod scan;
mod seal;
mod symbol;

pub(crate) use decode::{absorb_into_session, RelocationAddend, RelocationRecord};
pub(crate) use features::DynamicFeatureSummary;
pub(crate) use image_loader::{read_u16, read_u32, read_u64, ImageLoader};
pub(crate) use inspect::StackKind;
pub(crate) use map::LoadedRegion;
pub(crate) use scan::ScannedArtifact;
pub use seal::{
    PreparedProtectionPlan, ProtectionBatch, ProtectionCapabilities, ProtectionLevel,
    ProtectionRecord, SealPlan,
};

pub(crate) use metadata::{
    ArtifactRole, DependencyName, ImageLifecycleMetadata, ProgramHeaderGeometry,
    ProgramHeaderRuntimeInfo, RuntimeImageMetadata, RuntimeImageState,
};
pub(crate) use symbol::{
    symbol_count_from_hash, SymbolBinding, SymbolDefinition, SymbolEntry, SymbolTable, SymbolType,
    SymbolVisibility,
};
