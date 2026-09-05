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

//! Application package catalog (C30, §6.1).
//!
//! The build compiles the generated, build-time verified package manifests
//! into a standalone rlib (`app_package_catalog`); this module is the kernel's
//! view over it: the frozen per-package closure the resolver follows and the
//! boot seed copies into the root tmpfs. The catalog is built-in firmware
//! data, not a signature or an installation manifest (Phase 3 adds those).

pub use app_package_catalog::{
    image_blob, ApplicationPackageManifest, DeclaredDependency, DependencySource,
    PackageImageEntry, PackageImageRole,
};

/// The built-in application packages.
#[inline]
pub fn packages() -> &'static [ApplicationPackageManifest] {
    app_package_catalog::PACKAGES
}

/// The package whose root lives at `path`, if any.
pub fn find_root(path: &str) -> Option<&'static ApplicationPackageManifest> {
    packages().iter().find(|package| package.root.path == path)
}

/// The package-private image whose SONAME is `soname`, if any.
pub fn find_private_image(
    package: &'static ApplicationPackageManifest,
    soname: &[u8],
) -> Option<&'static PackageImageEntry> {
    package
        .private_images
        .iter()
        .copied()
        .find(|entry| entry.soname == Some(soname))
}

/// The declared dependency edge for `soname` from `requester`, if any.
pub fn find_edge(
    entry: &PackageImageEntry,
    soname: &[u8],
) -> Option<&'static DeclaredDependency> {
    entry.needed.iter().find(|edge| edge.soname == soname)
}

/// Map a package's target profile id to its loader profile (§9.1: the board
/// policy picks the profile; the package records it in the manifest). Unknown
/// ids fail closed rather than deriving ABI policy from an untrusted ELF.
pub fn profile_for(
    package: &ApplicationPackageManifest,
) -> Result<blueos_loader::LoadProfile, ()> {
    match package.profile {
        "thumbv7m-vivo-blueos-newlibeabi" => Ok(blueos_loader::LoadProfile::arm_thumb_soft_float(
            blueos_loader::ElfType::Dyn,
        )),
        "thumbv8m-main-vivo-blueos-newlibeabihf" => Ok(
            blueos_loader::LoadProfile::arm_thumb_hard_float(blueos_loader::ElfType::Dyn),
        ),
        "riscv64-vivo-blueos" => Ok(blueos_loader::LoadProfile::riscv64(
            blueos_loader::ElfType::Dyn,
        )),
        "aarch64-vivo-blueos" => Ok(blueos_loader::LoadProfile::aarch64(
            blueos_loader::ElfType::Dyn,
        )),
        "riscv32-vivo-blueos-imac" | "riscv32-vivo-blueos-imc" => Ok(
            blueos_loader::LoadProfile::riscv32(blueos_loader::ElfType::Dyn),
        ),
        _ => Err(()),
    }
}
