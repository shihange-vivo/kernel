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

use crate::{elf::ElfHeaderInfo, identity::LoadRequest, reader::ElfReader};

pub(crate) struct AdmittedImage<R: ElfReader> {
    reader: R,
    header: ElfHeaderInfo,
    request: LoadRequest,
    file_len: u64,
}

impl<R: ElfReader> AdmittedImage<R> {
    #[inline]
    pub const fn new(
        reader: R,
        header: ElfHeaderInfo,
        request: LoadRequest,
        file_len: u64,
    ) -> Self {
        Self {
            reader,
            header,
            request,
            file_len,
        }
    }

    #[inline]
    pub const fn reader(&self) -> &R {
        &self.reader
    }

    #[inline]
    pub const fn header(&self) -> &ElfHeaderInfo {
        &self.header
    }

    #[inline]
    pub const fn request(&self) -> &LoadRequest {
        &self.request
    }

    #[inline]
    pub const fn file_len(&self) -> u64 {
        self.file_len
    }
}
