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

//! Calculate standalone relative relocations and apply checked writes.

mod writes;

use crate::{
    elf::{LoadSegmentInfo, RelocationRecord},
    error::LoadErrorKind,
    memory::{ImageMapping, TargetAddress},
    profile::LoadProfile,
    LoadError, LoadResult,
};

pub(crate) fn apply_relative(
    allocation: &mut impl ImageMapping,
    profile: &LoadProfile,
    segments: &[LoadSegmentInfo],
    image_start: TargetAddress,
    records: &[RelocationRecord],
) -> LoadResult<()> {
    let bias = i128::from(allocation.base().get()) - i128::from(image_start.get());
    let writes = writes::plan(
        allocation,
        profile.class(),
        profile.endian(),
        segments,
        image_start,
        records,
        |record| {
            let Some(addend) = profile.check_relative_relocation(record)? else {
                return Ok(None);
            };
            if record.symbol_index() != 0 {
                return Err(record_error(record, LoadErrorKind::BadElf));
            }
            Ok(Some(bias + i128::from(addend)))
        },
    )?;
    writes.apply(allocation)
}

fn record_error(record: &RelocationRecord, kind: LoadErrorKind) -> LoadError {
    LoadError::relocation(
        record.offset(),
        record.raw_type(),
        record.symbol_index(),
        kind,
    )
}
