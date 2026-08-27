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

mod layout;
mod loaded;
mod metadata;
mod parser;
mod seal;

pub use layout::{
    ImageLayout, ImageLayoutBuilder, PlannedArtifact, SegmentLayout, SegmentLocation,
};
pub use loaded::{LoadedRegion, MappedImage, MappedState};
pub use metadata::{
    ArtifactFeaturePolicy, DynamicFeatureSummary, ProgramFeatureSummary, RelocationAddend,
    Phase0ArtifactPolicy, RelocationRecord, RuntimeImage, RuntimeImageMetadata, RuntimeState,
};
pub use parser::{DynamicSegmentInfo, LoadSegmentInfo, ParsedImage, StackPolicy};
pub use seal::{
    AppliedProtection, AppliedProtectionSet, PreparedImage, PreparedProtectionPlan,
    ProtectionCapabilities, ProtectionLevel, ReadyImageCommit, SealPlan, SealRange, SealedState,
};
