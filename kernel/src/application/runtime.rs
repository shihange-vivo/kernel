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

//! Boot-time dynamic application runtime assembly (C29, §18.2).
//!
//! [`super::seed`] installs the embedded ELF/DSO bytes into the VFS. This
//! module independently assembles the loader, registry, manager and reaper
//! over the fixed system-library catalog, and later launches the bootstrap
//! shell from the dedicated kernel image.

use alloc::vec::Vec;

use blueos_loader::LinkDomainId;

use crate::application::{
    adapters::system_paths::{SystemLibraryEntry, SystemLibraryPaths},
    service::ApplicationService,
};

/// The fixed system library catalog (§12.2): each `DT_NEEDED` resolves to
/// this VFS path. C31-a adds the second system DSO for the scope corpus's
/// non-interpose case (§17.2).
static SYSTEM_LIBRARIES: &[SystemLibraryEntry] = &[
    SystemLibraryEntry {
        lookup_name: b"libc.so.1",
        path: "/system/lib/libc.so.1",
        build_id: None,
        // The shared libc has unmodeled escapes (kernel callbacks, global
        // function pointers): never unload it (§8.5).
        keep_cached: true,
    },
    SystemLibraryEntry {
        // This fixture deliberately has no DT_SONAME. Linking records its
        // build filename while the catalog path remains the stable registry
        // key, proving that lookup metadata and ELF metadata are independent.
        lookup_name: b"libscope_sys.so",
        path: "/system/lib/libscope_sys.so.1",
        build_id: None,
        // The scope corpus's test system DSO has no escapes: the C31-d
        // reaper runs its fini and unloads it on quiescence, and the next
        // launch reloads generation+1.
        keep_cached: false,
    },
];
static CATALOG: SystemLibraryPaths = SystemLibraryPaths::new(SYSTEM_LIBRARIES);

/// Initialize the dynamic application runtime over the installed system image.
///
/// This does not write or replace any VFS file. The underlying service is a
/// `Once` singleton, so later calls return the already assembled runtime.
pub fn init() -> &'static ApplicationService {
    ApplicationService::init(&CATALOG, LinkDomainId::new(1))
}

/// Launch the dynamic bootstrap shell from the dedicated boot image.
///
/// Boot must have called [`init`] first. A launch failure is logged but is not
/// fatal: the runtime stays available for diagnostics or a later explicit
/// spawn.
pub fn launch_bootstrap_shell() {
    let service = ApplicationService::get()
        .expect("dynamic application runtime must be initialized before launching the shell");
    let argv = alloc::vec![b"/apps/shell/app.elf".to_vec()];
    if let Err(error) = service.spawn("/apps/shell/app.elf", argv, Vec::new()) {
        log::error!("boot: bootstrap shell launch failed: {:?}", error);
    }
}

/// The system catalog used by the boot-time dynamic application runtime.
pub fn catalog() -> &'static SystemLibraryPaths {
    &CATALOG
}
