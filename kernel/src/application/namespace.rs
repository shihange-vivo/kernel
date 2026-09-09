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

//! The launch-time path namespace (§3/§4 of the namespace-replacement plan).
//!
//! [`ApplicationNamespace`] freezes everything path-dependent about one
//! launch: the working directory observed at launch start, the resolved
//! absolute root path, the application-private directory layout, the board
//! profile and the system link domain. It is captured exactly once per launch
//! so a `chdir()` mid-load cannot change what later `DT_NEEDED` entries mean
//! (the VFS working directory is still process-global; §3.2).
//!
//! Dependency-request classification (absolute path / relative path / plain
//! name) and the search order (private `lib/` first, system catalog as
//! fallback) live here too, as pure string decisions; the caller performs the
//! actual VFS operations.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use blueos_loader::{LinkDomainId, LoadProfile};

use crate::vfs::{join_path, normalize_path};

/// One launch's frozen path namespace and link policy.
pub struct ApplicationNamespace {
    /// The working directory captured when this launch started (§3.2).
    launch_pwd: String,
    /// The root ELF path, resolved against `launch_pwd` and normalized.
    root_path: String,
    /// The parent directory of `root_path` (§3.1).
    application_root: String,
    /// `<application_root>/lib`: the first search directory for plain-name
    /// dependency requests from this application's own images.
    private_lib_dir: String,
    /// The board ELF/ABI policy the root links under.
    profile: LoadProfile,
    /// The shared domain system DSOs are registered under.
    system_domain: LinkDomainId,
}

impl ApplicationNamespace {
    /// Build the namespace for one launch: resolve `input_path` against the
    /// caller-captured pwd snapshot, then derive the application layout.
    ///
    /// `input_path` may be absolute, or relative to `launch_pwd` (which must
    /// itself be an absolute, normalized path — see
    /// [`crate::vfs::path::get_working_dir`]).
    pub fn from_launch_path(
        input_path: &str,
        launch_pwd: &str,
        profile: LoadProfile,
        system_domain: LinkDomainId,
    ) -> Option<Self> {
        if input_path.is_empty() {
            return None;
        }
        // Launch input is user-supplied, not VFS-internal: resolve relative
        // inputs against the captured pwd (§3.2), then normalize.
        let root_path = if input_path.starts_with('/') {
            normalize_path(input_path)?
        } else {
            join_path(launch_pwd, input_path)?
        };
        if !root_path.starts_with('/') {
            // A relative input with more `..` than the pwd has depth escapes
            // the root; such a launch has no absolute meaning.
            return None;
        }
        let application_root = parent_dir(&root_path)?;
        let private_lib_dir = join_path(&application_root, "lib")?;
        Some(Self {
            launch_pwd: launch_pwd.to_string(),
            root_path,
            application_root,
            private_lib_dir,
            profile,
            system_domain,
        })
    }

    /// The pwd snapshot this namespace was resolved against.
    pub fn launch_pwd(&self) -> &str {
        &self.launch_pwd
    }

    /// The normalized absolute root ELF path.
    pub fn root_path(&self) -> &str {
        &self.root_path
    }

    /// The root's parent directory.
    pub fn application_root(&self) -> &str {
        &self.application_root
    }

    /// `<application_root>/lib`.
    pub fn private_lib_dir(&self) -> &str {
        &self.private_lib_dir
    }

    /// The board profile for this launch.
    pub fn profile(&self) -> LoadProfile {
        self.profile
    }

    /// The shared system link domain.
    pub fn system_domain(&self) -> LinkDomainId {
        self.system_domain
    }
}

/// The directory a relative `DT_NEEDED`/`dlopen` request resolves against
/// (§4.2). Launch-time `DT_NEEDED` uses the requester ELF's directory;
/// an explicit `dlopen("./x.so")` will use the calling group's cwd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveBase<'a> {
    /// The directory containing the requesting ELF.
    RequesterDirectory(&'a str),
    /// The working directory captured at request time.
    CurrentWorkingDirectory(&'a str),
}

/// How one dependency request string is classified (§4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyKind {
    /// Starts with `/`: resolved as the exact normalized absolute path.
    Absolute,
    /// Contains `/` but is not absolute: resolved against the
    /// [`ResolveBase`] directory, then normalized. Also an exact request.
    Relative,
    /// No `/`: searched by name — `<private_lib_dir>/<name>` first, then the
    /// system catalog (§4.3).
    PlainName,
}

impl DependencyKind {
    /// Classify a `DT_NEEDED` string by its separators (§4).
    pub fn classify(request: &str) -> Self {
        if request.starts_with('/') {
            Self::Absolute
        } else if request.contains('/') {
            Self::Relative
        } else {
            Self::PlainName
        }
    }
}

/// Resolve one dependency request against `namespace` and `base` into the
/// concrete paths the caller should try, in order (§4.1–§4.3).
///
/// Returns the candidate absolute paths; a system-catalog hit is decided by
/// the caller comparing the final path against the catalog (a path request
/// that equals a catalog entry's path is a system DSO, §4.1 rule 2). A
/// relative path that escapes above `/` resolves to no candidate.
pub fn resolve_dependency_paths(
    namespace: &ApplicationNamespace,
    base: ResolveBase<'_>,
    request: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if request.is_empty() {
        return candidates;
    }
    match DependencyKind::classify(request) {
        DependencyKind::Absolute => {
            if let Some(path) = normalize_path(request) {
                candidates.push(path);
            }
        }
        DependencyKind::Relative => {
            let base_dir = match base {
                ResolveBase::RequesterDirectory(dir) => dir,
                ResolveBase::CurrentWorkingDirectory(dir) => dir,
            };
            if let Some(path) = join_path(base_dir, request)
                && path.starts_with('/')
            {
                candidates.push(path);
            }
        }
        // §4.3: private lib directory first, then the system catalog by
        // name. The catalog's contribution is the caller's lookup; here we
        // only produce the private candidate.
        DependencyKind::PlainName => {
            if let Some(path) = join_path(namespace.private_lib_dir(), request) {
                candidates.push(path);
            }
        }
    }
    candidates
}

/// The parent directory of an absolute normalized path: everything before
/// the final `/` component, or `/` itself for top-level entries.
fn parent_dir(path: &str) -> Option<String> {
    debug_assert!(path.starts_with('/'));
    let trimmed = path.trim_end_matches('/');
    let parent = match trimmed.rfind('/') {
        // "/x" → "/"
        Some(0) => "/",
        // "/a/b" → "/a"
        Some(at) => &trimmed[..at],
        // A single-component path ("x") never reaches here for absolute
        // inputs, but keep the invariant total rather than panicking.
        None => return None,
    };
    Some(String::from(parent))
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use blueos_test_macro::test;
    #[cfg(use_defmt)]
    use defmt::println;
    #[cfg(not(use_defmt))]
    use semihosting::println;

    use super::*;
    use crate::application::board_dynamic_profile;
    use blueos_loader::LinkDomainId;

    fn namespace(pwd: &str, input: &str) -> Option<ApplicationNamespace> {
        ApplicationNamespace::from_launch_path(
            input,
            pwd,
            board_dynamic_profile(),
            LinkDomainId::new(1),
        )
    }

    #[test]
    fn absolute_launch_path_is_normalized_as_is() {
        let ns = namespace("/apps", "/apps/multi/app.elf").expect("namespace");
        assert_eq!(ns.root_path(), "/apps/multi/app.elf");
        assert_eq!(ns.application_root(), "/apps/multi");
        assert_eq!(ns.private_lib_dir(), "/apps/multi/lib");
    }

    #[test]
    fn relative_launch_path_resolves_against_pwd() {
        // "cd /apps/hello && run app.elf" (§13.1)
        let ns = namespace("/apps/hello", "app.elf").expect("namespace");
        assert_eq!(ns.root_path(), "/apps/hello/app.elf");
        // "run apps/hello/app.elf" from the root (§13.1)
        let ns = namespace("/", "apps/hello/app.elf").expect("namespace");
        assert_eq!(ns.root_path(), "/apps/hello/app.elf");
    }

    #[test]
    fn dotdot_components_normalize() {
        let ns = namespace("/apps/multi", "./lib/../app.elf").expect("namespace");
        assert_eq!(ns.root_path(), "/apps/multi/app.elf");
    }

    #[test]
    fn root_launch_has_root_application_dir() {
        let ns = namespace("/", "/app.elf").expect("namespace");
        assert_eq!(ns.application_root(), "/");
        assert_eq!(ns.private_lib_dir(), "/lib");
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(namespace("/apps", "").is_none());
    }

    #[test]
    fn dependency_kind_classification() {
        assert_eq!(
            DependencyKind::classify("/vendor/lib/libfoo.so"),
            DependencyKind::Absolute
        );
        assert_eq!(
            DependencyKind::classify("./lib/libfoo.so"),
            DependencyKind::Relative
        );
        assert_eq!(
            DependencyKind::classify("../shared/libbar.so"),
            DependencyKind::Relative
        );
        assert_eq!(
            DependencyKind::classify("plugins/libcodec.so"),
            DependencyKind::Relative
        );
        assert_eq!(
            DependencyKind::classify("libfoo.so.1"),
            DependencyKind::PlainName
        );
        assert_eq!(DependencyKind::classify(""), DependencyKind::PlainName);
    }

    #[test]
    fn absolute_dependency_resolves_to_exact_path() {
        let ns = namespace("/apps", "/apps/multi/app.elf").expect("namespace");
        let paths = resolve_dependency_paths(
            &ns,
            ResolveBase::RequesterDirectory("/apps/multi"),
            "/system/lib/libc.so.1",
        );
        assert_eq!(paths, alloc::vec![String::from("/system/lib/libc.so.1")]);
    }

    #[test]
    fn relative_dependency_resolves_against_requester_directory() {
        let ns = namespace("/apps/foo", "/apps/foo/app.elf").expect("namespace");
        // root-relative (§4.2 first example)
        let paths = resolve_dependency_paths(
            &ns,
            ResolveBase::RequesterDirectory("/apps/foo"),
            "./lib/libfoo.so",
        );
        assert_eq!(paths, alloc::vec![String::from("/apps/foo/lib/libfoo.so")]);
        // DSO-relative (§4.2 second example)
        let paths = resolve_dependency_paths(
            &ns,
            ResolveBase::RequesterDirectory("/apps/foo/lib"),
            "./libbar.so",
        );
        assert_eq!(paths, alloc::vec![String::from("/apps/foo/lib/libbar.so")]);
    }

    #[test]
    fn plain_name_dependency_resolves_to_private_lib_first() {
        let ns = namespace("/apps/foo", "/apps/foo/app.elf").expect("namespace");
        let paths = resolve_dependency_paths(
            &ns,
            ResolveBase::RequesterDirectory("/apps/foo"),
            "libfoo.so.1",
        );
        assert_eq!(
            paths,
            alloc::vec![String::from("/apps/foo/lib/libfoo.so.1")]
        );
    }

    #[test]
    fn escaping_relative_dependency_clamps_to_root() {
        // The kernel's normalize_path (like the VFS's own open) treats a
        // relative path whose `..` run escapes above `/` as clamped to the
        // root rather than rejected: the candidate is `/etc/passwd`.
        let ns = namespace("/apps/foo", "/apps/foo/app.elf").expect("namespace");
        let paths = resolve_dependency_paths(
            &ns,
            ResolveBase::RequesterDirectory("/"),
            "../../../etc/passwd",
        );
        assert_eq!(paths, alloc::vec![String::from("/etc/passwd")]);
    }

    #[test]
    fn empty_dependency_request_resolves_to_nothing() {
        let ns = namespace("/apps/foo", "/apps/foo/app.elf").expect("namespace");
        let paths = resolve_dependency_paths(&ns, ResolveBase::RequesterDirectory("/apps/foo"), "");
        assert!(paths.is_empty());
    }
}
