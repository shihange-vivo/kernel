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

//! Loaded image metadata, lookup scopes, lifecycle plans and retention facts.

use alloc::{sync::Arc, vec::Vec};

pub use crate::dynamic_linker::ImageDependency;

use crate::{
    dynamic_linker::{
        order_components, ImageId, ImageOwnership, ImportedImageDescriptor, LifecyclePlans,
        LinkContext, PublishedImageDescriptor, RelocationBinding,
    },
    error::{invalid, oom},
    memory::TargetAddress,
    planning::LoadPlan,
    LoadResult,
};

/// An opaque loaded provider. Its allocation and reference counts belong to
/// the backend; holding this metadata handle does not itself pin that backing.
#[derive(Clone, Debug)]
pub struct ImageHandle {
    pub(crate) descriptor: Arc<PublishedImageDescriptor>,
    shared: bool,
}

impl ImageHandle {
    pub fn identity(&self) -> &[u8] {
        self.descriptor.identity().as_bytes()
    }
    pub const fn is_shared(&self) -> bool {
        self.shared
    }
    /// The original ordered DT_NEEDED bindings, frozen at publication.
    pub fn dependencies(&self) -> &[ImageDependency] {
        self.descriptor.snapshot().dependencies()
    }
    /// Find a visible defined export; the backend must still pin its backing.
    pub fn lookup_export(&self, name: &[u8]) -> Option<TargetAddress> {
        self.descriptor.lookup_export(name)
    }
    pub(crate) fn imported(&self) -> ImportedImageDescriptor {
        if self.shared {
            ImportedImageDescriptor::new(self.descriptor.clone())
        } else {
            ImportedImageDescriptor::namespace(self.descriptor.clone())
        }
    }
}

struct ImageFacts {
    handle: ImageHandle,
    newly_loaded: bool,
    lookup: Vec<ImageHandle>,
    component: Vec<ImageHandle>,
    dependencies: Vec<ImageHandle>,
    fini: Vec<usize>,
}

pub(crate) struct LoadFacts {
    pub(crate) entry: Option<TargetAddress>,
    images: Vec<ImageFacts>,
    retained: Vec<ImageHandle>,
    startup: Vec<usize>,
    fini: Vec<usize>,
    rollback_fini: Vec<usize>,
}

impl LoadFacts {
    pub(crate) fn metadata_bytes(&self) -> u64 {
        let handle_bytes = core::mem::size_of::<ImageHandle>();
        let mut bytes = core::mem::size_of::<Self>()
            + self.images.capacity() * core::mem::size_of::<ImageFacts>()
            + self.retained.capacity() * handle_bytes
            + (self.startup.capacity() + self.fini.capacity() + self.rollback_fini.capacity())
                * core::mem::size_of::<usize>();
        for image in &self.images {
            bytes += (image.lookup.capacity()
                + image.component.capacity()
                + image.dependencies.capacity())
                * handle_bytes;
            bytes += image.fini.capacity() * core::mem::size_of::<usize>();
        }
        bytes as u64
    }
}

/// A complete load with kernel-owned resource lifetime and opaque image metadata.
#[must_use = "the publication receipt must be installed or released"]
pub struct LoadedImage<Receipt> {
    receipt: Receipt,
    facts: LoadFacts,
}

impl<Receipt> LoadedImage<Receipt> {
    pub(crate) fn new(receipt: Receipt, facts: LoadFacts) -> Self {
        Self { receipt, facts }
    }

    /// A validated executable entry, absent for a shared-object root.
    pub fn entry(&self) -> Option<TargetAddress> {
        self.facts.entry
    }
    /// The complete requested closure in root-first breadth-first order.
    pub fn images(&self) -> impl Iterator<Item = &ImageHandle> {
        self.facts.images.iter().map(|image| &image.handle)
    }
    /// Reused dependencies and existing providers selected by relocations,
    /// including providers found only through the global scope.
    pub fn retained_images(&self) -> &[ImageHandle] {
        &self.facts.retained
    }
    pub fn startup(&self) -> &[usize] {
        &self.facts.startup
    }
    pub fn fini(&self) -> &[usize] {
        &self.facts.fini
    }
    pub fn rollback_fini(&self) -> &[usize] {
        &self.facts.rollback_fini
    }
    pub fn is_new(&self, image: &ImageHandle) -> bool {
        self.image_facts(image)
            .is_some_and(|facts| facts.newly_loaded)
    }
    /// Root-first dependency scope for handle-based symbol lookup.
    pub fn lookup_scope(&self, image: &ImageHandle) -> &[ImageHandle] {
        self.image_facts(image)
            .map(|facts| facts.lookup.as_slice())
            .unwrap_or(&[])
    }
    /// Shared images that must quiesce together, in destructor order (the
    /// reverse of lifecycle image order). Both declared dependencies and actual
    /// relocation providers contribute retention edges and cycles.
    pub fn shared_component(&self, image: &ImageHandle) -> &[ImageHandle] {
        self.image_facts(image)
            .map(|facts| facts.component.as_slice())
            .unwrap_or(&[])
    }
    /// Outgoing declared dependencies and actual relocation providers outside
    /// this shared image's cycle. The registry retains these; internal cycle
    /// edges must not become counted references.
    pub fn shared_dependencies(&self, image: &ImageHandle) -> &[ImageHandle] {
        self.image_facts(image)
            .map(|facts| facts.dependencies.as_slice())
            .unwrap_or(&[])
    }
    /// Validated destructors owned by a newly loaded shared instance.
    pub fn image_fini(&self, image: &ImageHandle) -> &[usize] {
        self.image_facts(image)
            .map(|facts| facts.fini.as_slice())
            .unwrap_or(&[])
    }
    /// Root program-header address, entry size and count, for the startup auxv.
    pub fn program_headers(&self) -> (Option<TargetAddress>, u16, u16) {
        let headers = self.facts.images[0].handle.descriptor.program_headers();
        (
            headers.runtime_vaddr(),
            headers.entry_size(),
            headers.count(),
        )
    }
    pub fn receipt_mut(&mut self) -> &mut Receipt {
        &mut self.receipt
    }
    pub fn into_receipt(self) -> Receipt {
        self.receipt
    }
    fn image_facts(&self, image: &ImageHandle) -> Option<&ImageFacts> {
        self.facts
            .images
            .iter()
            .find(|facts| facts.handle.identity() == image.identity())
    }
}

pub(crate) fn handle(image: &crate::dynamic_linker::CommittedImage) -> ImageHandle {
    ImageHandle {
        descriptor: image.descriptor_handle(),
        shared: matches!(
            image.ownership(),
            ImageOwnership::SystemCandidate | ImageOwnership::ExternalReady
        ),
    }
}

fn shared_retention_edges<'a>(
    context: &'a LinkContext,
    bindings: &'a [RelocationBinding],
) -> impl Iterator<Item = (ImageId, ImageId)> + Clone + 'a {
    context
        .graph_edges()
        .iter()
        .map(|edge| (edge.requester(), edge.provider()))
        .chain(bindings.iter().filter_map(|binding| {
            binding
                .provider()
                .map(|provider| (binding.requester(), provider))
        }))
        .filter(|(requester, provider)| {
            [requester, provider].iter().all(|owner| {
                matches!(
                    context.images()[owner.get() as usize].ownership(),
                    ImageOwnership::SystemCandidate | ImageOwnership::ExternalReady
                )
            })
        })
}

pub(crate) fn build_facts<S, R>(
    plan: &LoadPlan<S, R>,
    context: &LinkContext,
    plans: &LifecyclePlans,
    bindings: &[RelocationBinding],
) -> LoadResult<LoadFacts> {
    // Keep lifetime SCCs separate from the DT_NEEDED lifecycle graph. Actual
    // bindings can add providers (and cycles) without changing constructor order.
    let components = order_components(
        context.images().len(),
        shared_retention_edges(context, bindings),
    )?;
    let mut facts = LoadFacts {
        entry: None,
        images: Vec::new(),
        retained: Vec::new(),
        startup: Vec::new(),
        fini: Vec::new(),
        rollback_fini: Vec::new(),
    };
    facts
        .images
        .try_reserve_exact(plan.images.len())
        .map_err(|_| oom())?;
    facts
        .retained
        .try_reserve_exact(context.images().len())
        .map_err(|_| oom())?;
    for (index, planned) in plan.images.iter().enumerate() {
        let image = context
            .images()
            .iter()
            .find(|image| image.descriptor().identity() == &planned.identity)
            .ok_or_else(invalid)?;
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(plan.images.len())
            .map_err(|_| oom())?;
        queue.push(index);
        let mut cursor = 0;
        while cursor < queue.len() {
            let requester = queue[cursor];
            for edge in plan.edges.iter().filter(|edge| edge.requester == requester) {
                if !queue.contains(&edge.provider) {
                    queue.push(edge.provider);
                }
            }
            cursor += 1;
        }
        let mut lookup = Vec::new();
        lookup.try_reserve_exact(queue.len()).map_err(|_| oom())?;
        for member in queue {
            let provider = context
                .images()
                .iter()
                .find(|image| image.descriptor().identity() == &plan.images[member].identity)
                .ok_or_else(invalid)?;
            lookup.push(handle(provider));
        }
        let scc = components
            .iter()
            .find(|members| members.contains(&image.owner()))
            .ok_or_else(invalid)?;
        let mut component = Vec::new();
        let mut dependencies = Vec::new();
        component.try_reserve_exact(scc.len()).map_err(|_| oom())?;
        dependencies
            .try_reserve_exact(context.images().len())
            .map_err(|_| oom())?;
        for owner in plans
            .sccs()
            .iter()
            .rev()
            .flat_map(|members| members.iter().rev())
        {
            if !scc.contains(owner) {
                continue;
            }
            let member = &context.images()[owner.get() as usize];
            let member = handle(member);
            if member.shared {
                component.push(member);
            }
        }
        for (_, provider) in shared_retention_edges(context, bindings)
            .filter(|(requester, provider)| *requester == image.owner() && !scc.contains(provider))
        {
            let provider = handle(&context.images()[provider.get() as usize]);
            if provider.shared
                && !dependencies
                    .iter()
                    .any(|image: &ImageHandle| image.identity() == provider.identity())
            {
                dependencies.push(provider);
            }
        }
        let mut fini = Vec::new();
        if let Some(plan) = plans
            .system_fini()
            .iter()
            .find(|plan| plan.owner() == image.owner())
        {
            copy_targets(&mut fini, plan.plan().iter())?;
        }
        let newly_loaded = matches!(
            image.ownership(),
            ImageOwnership::SessionPrivate | ImageOwnership::SystemCandidate
        );
        let image = handle(image);
        if !newly_loaded {
            facts.retained.push(image.clone());
        }
        facts.images.push(ImageFacts {
            handle: image,
            newly_loaded,
            lookup,
            component,
            dependencies,
            fini,
        });
    }
    for binding in bindings {
        if let Some(owner) = binding.provider() {
            let provider = &context.images()[owner.get() as usize];
            if matches!(
                provider.ownership(),
                ImageOwnership::ExternalReady | ImageOwnership::NamespaceReady
            ) {
                let provider = handle(provider);
                if !facts
                    .retained
                    .iter()
                    .any(|image| image.identity() == provider.identity())
                {
                    facts.retained.push(provider);
                }
            }
        }
    }
    copy_targets(&mut facts.startup, plans.startup().iter())?;
    copy_targets(&mut facts.fini, plans.group_fini().iter())?;
    facts
        .rollback_fini
        .try_reserve_exact(facts.fini.len())
        .map_err(|_| oom())?;
    facts.rollback_fini.extend_from_slice(&facts.fini);
    for plan in plans.system_fini() {
        copy_targets(&mut facts.rollback_fini, plan.plan().iter())?;
    }
    Ok(facts)
}

fn copy_targets<'a>(
    out: &mut Vec<usize>,
    entries: impl Iterator<Item = &'a crate::dynamic_linker::LifecycleEntry>,
) -> LoadResult<()> {
    for entry in entries {
        out.try_reserve(1).map_err(|_| oom())?;
        out.push(entry.function().get() as usize);
    }
    Ok(())
}
