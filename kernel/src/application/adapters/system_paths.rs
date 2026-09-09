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

//! Fixed system library catalog (C23-b, §12.2; namespace plan §6).
//!
//! The catalog is the board/product-provided mapping between the names plain
//! `DT_NEEDED` requests search for and the on-device DSO paths. Since the
//! namespace replacement (§5/§6 of the plan) a DSO may omit `DT_SONAME`, so
//! the entry's name and path are independent keys: `resolve_name` serves
//! plain-name lookups, `resolve_path` decides whether a path-resolved
//! dependency is a shared system DSO (the normalized catalog path is the
//! registry key). `resolve` keeps the legacy SONAME-keyed spelling for
//! current callers until step 4 re-keys the registry.

/// One fixed mapping from a system lookup name to its on-device path.
#[derive(Clone, Copy, Debug)]
pub struct SystemLibraryEntry {
    /// The `DT_SONAME` byte name, e.g. `b"libc.so.1"`, without a NUL.
    pub soname: &'static [u8],
    /// Absolute device path of the DSO, e.g. `"/system/lib/libc.so.1"`.
    pub path: &'static str,
    /// Expected build-id bytes when policy requires one; `None` accepts any
    /// build-id (or none) for this entry.
    pub build_id: Option<&'static [u8]>,
    /// Quiescence policy (C31-d, §8.5): `true` keeps the zero-lease instance
    /// cached for later imports (a DSO with unmodeled escapes, like the
    /// shared libc); `false` allows the reaper to run the instance's fini on
    /// its worker thread and release the backing, so `generation + 1` reloads
    /// it. Only set `false` for DSOs with no kernel callbacks or escaped
    /// function pointers.
    pub keep_cached: bool,
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

    /// Look up a plain dependency name (a `DT_NEEDED` string without path
    /// separators) by exact, case-sensitive comparison (§4.3 step 2).
    pub fn resolve_name(&self, name: &[u8]) -> Option<&'static SystemLibraryEntry> {
        self.entries.iter().find(|entry| entry.soname == name)
    }

    /// Look up an entry by its normalized absolute device path (§4.1 rule 2):
    /// a path-resolved dependency whose path equals a catalog entry's path is
    /// a shared system DSO, whatever `DT_SONAME` it carries. The returned
    /// entry's path doubles as the registry key (§6).
    pub fn resolve_path(&self, path: &str) -> Option<&'static SystemLibraryEntry> {
        self.entries.iter().find(|entry| entry.path == path)
    }

    /// Look up a `DT_NEEDED`/`DT_SONAME` byte name by exact, case-sensitive
    /// comparison. Returns `None` when the name is not in the catalog, which
    /// the resolver treats as an unresolved system dependency (§12.2).
    pub fn resolve(&self, soname: &[u8]) -> Option<&'static SystemLibraryEntry> {
        self.resolve_name(soname)
    }
}
