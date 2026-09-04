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

//! Fixed system library catalog (C23-b, §12.2).
//!
//! Phase 1 resolves system dependencies only through an exact byte-name
//! lookup against a board/product-provided mapping — never the current
//! directory, `LD_LIBRARY_PATH`, `RPATH`/`RUNPATH`, or an application
//! package `lib/` directory. Each entry pairs a `DT_SONAME` with its absolute
//! path and, where policy requires it, an expected build-id.

/// One fixed mapping from a system `DT_SONAME` to its on-device path.
#[derive(Clone, Copy, Debug)]
pub struct SystemLibraryEntry {
    /// The `DT_SONAME` byte name, e.g. `b"libc.so.1"`, without a NUL.
    pub soname: &'static [u8],
    /// Absolute device path of the DSO, e.g. `"/system/lib/libc.so.1"`.
    pub path: &'static str,
    /// Expected build-id bytes when policy requires one; `None` accepts any
    /// build-id (or none) for this entry.
    pub build_id: Option<&'static [u8]>,
}

/// A fixed, board/product-configured system library catalog.
///
/// The mapping is static: it cannot be mutated at runtime, which keeps the
/// resolver's catalog keyed on immutable byte names rather than a writable
/// directory scan.
pub struct SystemLibraryPaths {
    entries: &'static [SystemLibraryEntry],
}

impl SystemLibraryPaths {
    /// Build a catalog from a static, board-provided entry table.
    pub const fn new(entries: &'static [SystemLibraryEntry]) -> Self {
        Self { entries }
    }

    /// Look up a `DT_NEEDED`/`DT_SONAME` byte name by exact, case-sensitive
    /// comparison. Returns `None` when the name is not in the catalog, which
    /// the resolver treats as an unresolved system dependency (§12.2).
    pub fn resolve(&self, soname: &[u8]) -> Option<&'static SystemLibraryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.soname == soname)
    }
}
