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

//! Assemble independent loader capabilities. Runtime installation belongs to the caller.
use super::{
    adapters::{
        code_cache::ArchitectureCodeCache, flat_memory::FlatImageMemory,
        resolver::NamespaceSourceResolver, system_paths::SystemLibraryPaths,
    },
    group::ThreadGroup,
    namespace::ApplicationNamespace,
    publication::{KernelLinkPublisher, KernelLinkReceipt},
    registry::{SystemDsoRegistry, SystemInitBatch},
    repository::{KernelImagePin, KernelImageRepository},
    trace,
};
use alloc::vec::Vec;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    load,
    memory::CacheRequirements,
    profile::SessionLimits,
    ImagePin, LoadError, LoadRequest, LoadResult, LoadServices, LoadedImage, NamespaceSnapshot,
};

pub struct ApplicationLoader {
    catalog: &'static SystemLibraryPaths,
    registry: SystemDsoRegistry,
    memory: FlatImageMemory,
}
impl ApplicationLoader {
    pub fn new(
        catalog: &'static SystemLibraryPaths,
        registry: SystemDsoRegistry,
        memory: FlatImageMemory,
    ) -> Self {
        Self {
            catalog,
            registry,
            memory,
        }
    }
    pub fn registry(&self) -> &SystemDsoRegistry {
        &self.registry
    }
    pub fn catalog(&self) -> &'static SystemLibraryPaths {
        self.catalog
    }
    pub fn memory(&self) -> &FlatImageMemory {
        &self.memory
    }
    pub fn link(
        &self,
        namespace: &ApplicationNamespace,
        group: &ThreadGroup,
    ) -> LoadResult<LoadedImage<KernelLinkReceipt>> {
        self.link_inner(
            namespace,
            namespace.root_path(),
            group,
            false,
            Vec::new(),
            Vec::new(),
        )
    }
    pub(crate) fn link_shared(
        &self,
        namespace: &ApplicationNamespace,
        path: &str,
        group: &ThreadGroup,
        existing: Vec<KernelImagePin>,
        global: Vec<blueos_loader::ImageInstanceId>,
    ) -> LoadResult<(LoadedImage<KernelLinkReceipt>, SystemInitBatch)> {
        let mut product = self.link_inner(namespace, path, group, true, existing, global)?;
        let batch = product.receipt_mut().take_pending()?;
        Ok((product, batch))
    }
    fn link_inner(
        &self,
        namespace: &ApplicationNamespace,
        path: &str,
        group: &ThreadGroup,
        shared: bool,
        existing: Vec<KernelImagePin>,
        global: Vec<blueos_loader::ImageInstanceId>,
    ) -> LoadResult<LoadedImage<KernelLinkReceipt>> {
        // The core can link foreign profiles into non-native memory. This host
        // launches native threads, so retain the former native-only ABI gate here.
        let profile = namespace.profile();
        let native = super::board_dynamic_profile();
        if profile.machine() != native.machine()
            || profile.class() != native.class()
            || profile.endian() != native.endian()
            || profile.header_flags() != native.header_flags()
            || profile.entry_mode() != native.entry_mode()
        {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::None,
            ));
        }
        let mut files = NamespaceSourceResolver::new(
            namespace,
            self.catalog,
            group.namespace_scope(),
            existing.iter().map(|p| p.image().clone()).collect(),
        );
        let source = files.root(path, !shared)?;
        let mut repository = KernelImageRepository::new(
            self.registry.clone(),
            existing.clone(),
            self.memory.clone(),
        );
        let request = if shared {
            LoadRequest::shared_object(source, namespace.profile(), SessionLimits::DEFAULT)
        } else {
            LoadRequest::executable(source, namespace.profile(), SessionLimits::DEFAULT)
        };
        let request = request.with_namespace(NamespaceSnapshot::new(existing, global)?);
        let mut cache = ArchitectureCodeCache::new(CacheRequirements::CURRENT_EXECUTION_CONTEXT);
        let mut observer = KernelLoadObserver {
            group: group.clone(),
            id: trace::new_load_id(),
        };
        let mut publisher =
            KernelLinkPublisher::new(self.memory.clone(), self.registry.clone(), self.catalog);
        load(
            request,
            LoadServices {
                sources: &mut files,
                images: &mut repository,
                memory: self.memory.clone(),
                cache: &mut cache,
                observer: &mut observer,
            },
            &mut publisher,
        )
    }
}
struct KernelLoadObserver {
    group: ThreadGroup,
    id: usize,
}
impl blueos_loader::trace::LoadObserver for KernelLoadObserver {
    fn enabled(&self) -> bool {
        self.id != 0
    }
    fn observe(&mut self, event: blueos_loader::trace::LoadEvent<'_>) {
        trace::emit(trace::Event::Load {
            application: self.group.handle(),
            operation: self.id,
            event,
        });
    }
}
pub(crate) fn loader_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}
pub(crate) fn loader_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}

#[cfg(test)]
mod native_profile_tests {
    use super::*;
    use blueos_test_macro::test;
    #[test]
    fn native_host_rejects_foreign_profiles_before_opening_files() {
        static CATALOG: SystemLibraryPaths = SystemLibraryPaths::new(&[]);
        let registry = SystemDsoRegistry::new();
        let group = ThreadGroup::new(&registry);
        let loader = ApplicationLoader::new(&CATALOG, registry, FlatImageMemory::new());
        let profile = if super::super::board_dynamic_profile().machine()
            == blueos_loader::profile::ElfMachine::Aarch64
        {
            blueos_loader::profile::LoadProfile::riscv64()
        } else {
            blueos_loader::profile::LoadProfile::aarch64()
        };
        let namespace =
            ApplicationNamespace::from_launch_path("/does-not-exist", "/", profile).unwrap();
        assert_eq!(
            loader.link(&namespace, &group).err().unwrap().kind(),
            LoadErrorKind::UnsupportedByProfile
        );
    }
}
