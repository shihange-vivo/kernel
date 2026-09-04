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

//! Assembled application control plane (C25/C26 glue).
//!
//! [`ApplicationService`] is the single place where the dynamic application
//! stack is wired together: one [`ApplicationManager`], one
//! [`ApplicationLoader`], one [`SystemDsoRegistry`], one
//! [`FlatImageMemory`] service and one [`ApplicationReaper`], over a fixed
//! system library catalog and a fixed link domain. Boot bootstrap and the
//! `ApplicationLaunch` syscall both reach it through the same singleton and
//! call [`ApplicationService::spawn`]; there is no boot fast path that calls
//! a loader directly (§14.2).
//!
//! `spawn` is the manager's `prepare` closure (§14.2 steps 5–7): open the
//! root, run the staged link, pin the start storage, install the product,
//! and start the main thread at the relocated entry with the group
//! membership attached. Every failure before the install drops the armed
//! link session and cancels the registry permits; a failure after the
//! install moves the group to draining with a skipped fini so the deferred
//! reaper releases the installed product.

use alloc::vec::Vec;
use spin::Once;

use blueos_header::application::BlueOsStringView;
use blueos_loader::{ElfType, ImageProtectionMemory, LinkDomainId, LoadProfile};

use crate::{
    application::{
        adapters::{
            flat_memory::FlatImageMemory,
            system_paths::SystemLibraryPaths,
        },
        group::{ThreadGroup, ThreadGroupMembership},
        loader::ApplicationLoader,
        manager::{
            ApplicationHandle, ApplicationLaunchError, ApplicationManager, ExecutionModel,
            OwnedLaunchRequest,
        },
        reaper::ApplicationReaper,
        registry::SystemDsoRegistry,
        start_storage::ApplicationStartStorage,
    },
    scheduler,
    thread::{self, Builder, Entry},
};

/// The assembled application control plane (§14, §15).
pub struct ApplicationService {
    manager: ApplicationManager,
    loader: ApplicationLoader,
    reaper: ApplicationReaper,
}

static APPLICATION_SERVICE: Once<ApplicationService> = Once::new();

impl ApplicationService {
    /// Assemble the process-wide service over a fixed system library catalog
    /// and a fixed link domain. Idempotent: later calls return the existing
    /// singleton.
    pub fn init(
        catalog: &'static SystemLibraryPaths,
        domain: LinkDomainId,
    ) -> &'static ApplicationService {
        APPLICATION_SERVICE.call_once(|| {
            let memory = FlatImageMemory::new();
            let registry = SystemDsoRegistry::new();
            let loader = ApplicationLoader::new(catalog, registry.clone(), memory.clone(), domain);
            let reaper = ApplicationReaper::new(registry, memory);
            let manager = ApplicationManager::new();
            // The deferred reaper thread owns clones of the reaper and the
            // manager and releases drained groups outside every manager lock
            // (§16.4).
            reaper.spawn(manager.clone());
            Self {
                manager,
                loader,
                reaper,
            }
        })
    }

    /// The singleton, once initialized.
    pub fn get() -> Option<&'static ApplicationService> {
        APPLICATION_SERVICE.get()
    }

    /// The application manager (§14).
    pub fn manager(&self) -> &ApplicationManager {
        &self.manager
    }

    /// The deferred reaper (C27, §16.4).
    pub fn reaper(&self) -> &ApplicationReaper {
        &self.reaper
    }

    /// Launch a dynamic application: link it against the system catalog,
    /// pin its start storage, install the product into a fresh thread group
    /// and start its main thread at the relocated entry (§14.2, §15).
    ///
    /// `argv`/`envp` are the owned, already-validated strings the launch
    /// syscall copied in; the returned handle stays `Loading` until the
    /// application reports `ApplicationInitComplete`.
    pub fn spawn(
        &self,
        path: &str,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
    ) -> Result<ApplicationHandle, ApplicationLaunchError> {
        let identity = path.as_bytes().to_vec();
        let result = self.manager.launch(
            OwnedLaunchRequest::new(ExecutionModel::ThreadGroup, identity.clone()),
            |group| self.prepare(group, path, &argv, &envp),
        );
        // Either way the group now belongs to the deferred reaper: a live
        // group is released after its members left and its fini resolved, a
        // failed launch's group (nothing installed, or installed-then-drained)
        // is recycled together with its `Failed` slot (§16.4).
        let handle = match result {
            Ok(handle) => Some(handle),
            Err(_) => self
                .manager
                .query_by_identity(&identity)
                .map(|snapshot| snapshot.handle),
        };
        if let Some(group) = handle.and_then(|handle| self.manager.group(handle)) {
            self.reaper.register(&group);
        }
        result
    }

    /// The manager's slow prepare closure: VFS open, staged link, start
    /// storage and main-thread creation all run outside the manager's table
    /// lock (§14.2 step 5).
    fn prepare(
        &self,
        group: &ThreadGroup,
        path: &str,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> Result<(), ApplicationLaunchError> {
        let argv_views: Vec<BlueOsStringView> = argv
            .iter()
            .map(|string| BlueOsStringView {
                data: string.as_ptr(),
                len: string.len(),
            })
            .collect();
        let envp_views: Vec<BlueOsStringView> = envp
            .iter()
            .map(|string| BlueOsStringView {
                data: string.as_ptr(),
                len: string.len(),
            })
            .collect();

        let root = self
            .loader
            .open_root(path, None)
            .map_err(|error| prepare_failed("open root", &error))?;
        let profile = LoadProfile::arm_thumb_soft_float(ElfType::Dyn);
        let product = self
            .loader
            .link(root, profile, group)
            .map_err(|error| prepare_failed("link application", &error))?;

        let handle = group
            .handle()
            .ok_or(ApplicationLaunchError::PrepareFailed)?;
        let granule = self
            .loader
            .memory()
            .protection_capabilities()
            .granule();
        let storage = ApplicationStartStorage::build(
            handle,
            path.as_bytes(),
            &argv_views,
            &envp_views,
            &product,
            granule,
        )
        .map_err(|_| ApplicationLaunchError::PrepareFailed)?;

        // The storage heap allocations never move; the pointer stays valid
        // after the install moved the storage into the group (§15.3).
        let start_info = storage.start_info_ptr();
        let entry = product.entry().get() as usize;
        group
            .install_link_product(product, storage)
            .map_err(|_| ApplicationLaunchError::PrepareFailed)?;

        let stack = thread::Stack::from_size(blueos_kconfig::CONFIG_MAIN_THREAD_STACK_SIZE as usize)
            .ok_or(ApplicationLaunchError::PrepareFailed)?;
        let main = Builder::new(Entry::Raw(entry, start_info as *mut core::ffi::c_void))
            .set_stack(stack)
            .set_membership(ThreadGroupMembership::downgrade(group))
            .build();
        if group.add_member(main.clone()).is_err() {
            // The product is installed but the main thread could not join:
            // move the group to draining with a skipped fini so the deferred
            // reaper releases the installed product (abnormal path, §16.4).
            let _ = group.begin_exit();
            let _ = group.skip_fini();
            return Err(ApplicationLaunchError::PrepareFailed);
        }
        let queued = scheduler::queue_ready_thread(thread::IDLE, main);
        if queued.is_err() {
            let _ = group.begin_exit();
            let _ = group.skip_fini();
            return Err(ApplicationLaunchError::PrepareFailed);
        }
        Ok(())
    }
}

fn prepare_failed(step: &str, error: &blueos_loader::LoadError) -> ApplicationLaunchError {
    log::error!("application prepare: {step} failed: {:?}", error);
    ApplicationLaunchError::PrepareFailed
}
