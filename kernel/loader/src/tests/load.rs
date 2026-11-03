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

use crate::{
    error::{ErrorContext, LimitKind, LoadErrorKind},
    loading::planning::LoadPlan,
    memory::{AllocationLease, AllocationOffset, ImageMemory, MemoryPermissions, MemoryRegion},
    profile::{LoadLimits, LoadProfile, SessionLimits},
    reader::ElfReader,
    tests::fixture::{SharedMemory, SliceElfReader},
    trace::{LoadEvent, LoadPhase},
    ArtifactId, ArtifactInfo, ArtifactResolver, ImageCandidate, ImageHandle, ImageInstanceId,
    ImageKey, ImagePin, ImageRepository, LoadError, LoadPublisher, LoadReservation, LoadResources,
    LoadResult, LoadServices, LoadedImage, NamespaceSnapshot, OpenedArtifact, PreparedLoad,
    PublicationManifest, ReservedImage,
};
use alloc::{rc::Rc, vec::Vec};
use blueos_test_macro::test;
use core::cell::RefCell;

// Avoid linking recursive Debug formatters into the small-board test image.
#[derive(Eq, PartialEq)]
enum Observation {
    Started,
    Phase(LoadPhase, bool),
    Inspected(bool),
    Dependency(Vec<u8>, Vec<u8>),
    Reused(Vec<u8>),
    Retry(usize),
    Completed,
    Failed {
        cancels: usize,
        releases: usize,
        backings: usize,
    },
}

struct Reader(Rc<[u8]>);
impl ElfReader for Reader {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        SliceElfReader::new(&self.0).read_exact_at(offset, dst)
    }
}
type LoadRequest<S> = crate::LoadRequest<S, Pin>;
#[must_use]
struct Receipt {
    inner: Rc<ReceiptInner>,
}
impl core::ops::Deref for Receipt {
    type Target = ReceiptInner;
    fn deref(&self) -> &ReceiptInner {
        &self.inner
    }
}
#[must_use]
struct ReceiptInner {
    memory: SharedMemory,
    leases: Vec<AllocationLease>,
    _pins: Vec<Pin>,
    _imports: Vec<Pin>,
}
impl Drop for ReceiptInner {
    fn drop(&mut self) {
        for lease in self.leases.drain(..) {
            self.memory.release_committed(lease);
        }
    }
}
impl Receipt {
    fn pin(&self, image: &ImageHandle) -> Pin {
        Pin {
            image: image.clone(),
            _owner: self.inner.clone(),
        }
    }
}
#[must_use]
#[derive(Clone)]
struct Pin {
    image: ImageHandle,
    _owner: Rc<ReceiptInner>,
}
// SAFETY: the shared receipt owns the backing and the transitive provider pins.
unsafe impl ImagePin for Pin {
    fn image(&self) -> &ImageHandle {
        &self.image
    }
}
fn namespace(pins: Vec<Pin>, global: Vec<ImageHandle>) -> NamespaceSnapshot<Pin> {
    NamespaceSnapshot::new(pins, global.iter().map(ImageHandle::instance_id).collect()).unwrap()
}
struct Backend {
    files: Vec<(&'static str, Rc<[u8]>)>,
    sources: Vec<&'static str>,
    ready: Vec<Pin>,
    ready_after_acquire: Vec<Pin>,
    opens: Vec<&'static str>,
    memory: SharedMemory,
    reject_acquire: bool,
    malformed_reservation: u8,
    reject_publish: bool,
    shared: bool,
    commits: usize,
    aborts: usize,
    cancels: usize,
    tracing: bool,
    observations: RefCell<Vec<Observation>>,
}
impl Backend {
    fn new(files: Vec<(&'static str, Vec<u8>)>) -> Self {
        Self {
            sources: files.iter().map(|(name, _)| *name).collect(),
            ready: Vec::new(),
            ready_after_acquire: Vec::new(),
            opens: Vec::new(),
            files: files
                .into_iter()
                .map(|(name, bytes)| (name, Rc::from(bytes)))
                .collect(),
            memory: SharedMemory::new(false),
            reject_acquire: false,
            malformed_reservation: 0,
            reject_publish: false,
            shared: false,
            commits: 0,
            aborts: 0,
            cancels: 0,
            tracing: false,
            observations: RefCell::new(Vec::new()),
        }
    }
}
fn failure() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}
#[derive(Clone)]
struct Source {
    name: &'static str,
    info: ArtifactInfo,
}
#[derive(Clone)]
struct Host<'a>(Rc<RefCell<&'a mut Backend>>);
impl ArtifactResolver for Host<'_> {
    type Source = Source;
    type Reader = Reader;
    fn info<'b>(&self, source: &'b Source) -> &'b ArtifactInfo {
        &source.info
    }
    fn resolve(&mut self, _: &Source, name: &[u8]) -> LoadResult<Source> {
        let b = self.0.borrow();
        let name = b
            .sources
            .iter()
            .find(|s| s.as_bytes() == name)
            .copied()
            .ok_or_else(failure)?;
        Ok(Source {
            name,
            info: ArtifactInfo::new(ImageKey::new(0, name.as_bytes())?, b.shared),
        })
    }
    fn open(&mut self, source: &Source) -> LoadResult<OpenedArtifact<Reader>> {
        let mut b = self.0.borrow_mut();
        b.opens.push(source.name);
        let bytes = b
            .files
            .iter()
            .find(|(name, _)| *name == source.name)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(failure)?;
        Ok(OpenedArtifact::new(Reader(bytes), ArtifactId::fresh()?))
    }
}
#[must_use]
struct Reservation<'a> {
    host: Host<'a>,
    reserved: Vec<ReservedImage>,
    imported: Vec<Pin>,
    armed: bool,
}
impl LoadReservation for Reservation<'_> {
    type Pin = Pin;
    fn reserved(&self) -> &[ReservedImage] {
        &self.reserved
    }
    fn imported(&self) -> &[Pin] {
        &self.imported
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.host.0.borrow_mut().cancels += 1;
        }
    }
}
impl<'a> ImageRepository for Host<'a> {
    type Pin = Pin;
    type Reservation = Reservation<'a>;
    fn snapshot(&mut self, key: &ImageKey) -> LoadResult<Option<Pin>> {
        Ok(self
            .0
            .borrow()
            .ready
            .iter()
            .find(|p| p.image.key() == key)
            .cloned())
    }
    fn pin_exact(&mut self, id: &ImageInstanceId) -> LoadResult<Pin> {
        self.0
            .borrow()
            .ready
            .iter()
            .find(|p| p.image.instance_id() == *id)
            .cloned()
            .ok_or_else(failure)
    }
    fn acquire(&mut self, candidates: &[ImageCandidate]) -> LoadResult<Self::Reservation> {
        let mut b = self.0.borrow_mut();
        if b.reject_acquire {
            return Err(failure());
        }
        b.memory.acquired.set(true);
        let arriving = core::mem::take(&mut b.ready_after_acquire);
        b.ready.extend(arriving);
        let imported: Vec<_> = b
            .ready
            .iter()
            .filter(|p| candidates.iter().any(|c| &c.key == p.image.key()))
            .cloned()
            .collect();
        let mut reserved = Vec::new();
        for c in candidates {
            if !imported.iter().any(|p| p.image.key() == &c.key) {
                reserved.push(ReservedImage {
                    key: c.key.clone(),
                    instance: ImageInstanceId::fresh()?,
                });
            }
        }
        match b.malformed_reservation {
            1 => reserved.push(reserved[0].clone()),
            2 => reserved.clear(),
            3 => reserved[0].key = ImageKey::new(0, b"unrequested")?,
            4 => reserved[1].instance = reserved[0].instance,
            _ => {}
        }
        Ok(Reservation {
            host: self.clone(),
            reserved,
            imported,
            armed: true,
        })
    }
}
impl<'a> LoadPublisher<SharedMemory, Pin, Reservation<'a>> for Host<'a> {
    type Prepared = Receipt;
    type Owner = Receipt;
    fn prepare(
        &mut self,
        publication: &PublicationManifest,
        _: &Reservation<'a>,
    ) -> LoadResult<Self::Prepared> {
        let b = self.0.borrow();
        if b.reject_publish {
            return Err(failure());
        }
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(publication.allocations().len())
            .map_err(|_| failure())?;
        Ok(Receipt {
            inner: Rc::new(ReceiptInner {
                memory: b.memory.clone(),
                leases,
                _pins: Vec::new(),
                _imports: Vec::new(),
            }),
        })
    }
    unsafe fn commit(
        &mut self,
        mut prepared: Self::Prepared,
        resources: LoadResources<SharedMemory, Pin, Reservation<'a>>,
    ) -> Receipt {
        let (_, allocations, pins, mut reservation) = unsafe { resources.into_parts() };
        let owner = Rc::get_mut(&mut prepared.inner).expect("unpublished owner");
        for (_, lease) in allocations {
            owner.leases.push(lease);
        }
        owner._pins = pins;
        owner._imports = core::mem::take(&mut reservation.imported);
        reservation.armed = false;
        self.0.borrow_mut().commits += 1;
        prepared
    }
}
impl crate::trace::LoadObserver for Host<'_> {
    fn enabled(&self) -> bool {
        self.0.borrow().tracing
    }
    fn observe(&mut self, event: LoadEvent<'_>) {
        let b = self.0.borrow();
        let observation = match event {
            LoadEvent::Started { .. } => Observation::Started,
            LoadEvent::Phase { phase, completed } => Observation::Phase(phase, completed),
            LoadEvent::Inspected { snapshot, .. } => Observation::Inspected(snapshot),
            LoadEvent::Dependency {
                requester,
                provider,
                ..
            } => Observation::Dependency(requester.to_vec(), provider.to_vec()),
            LoadEvent::ImageReused { path, .. } => Observation::Reused(path.to_vec()),
            LoadEvent::Retry => Observation::Retry(b.cancels),
            LoadEvent::Completed => Observation::Completed,
            LoadEvent::Failed { .. } => Observation::Failed {
                cancels: b.cancels,
                releases: b.memory.releases.get(),
                backings: b.memory.mappers.borrow().len(),
            },
            _ => return,
        };
        b.observations.borrow_mut().push(observation);
    }
}
fn request(request: LoadRequest<&'static str>, shared: bool) -> crate::LoadRequest<Source, Pin> {
    crate::LoadRequest {
        source: Source {
            name: request.source,
            info: ArtifactInfo::new(ImageKey::new(0, request.source.as_bytes()).unwrap(), shared),
        },
        profile: request.profile,
        limits: request.limits,
        role: request.role,
        namespace: request.namespace,
    }
}
fn load(
    input: LoadRequest<&'static str>,
    backend: &mut Backend,
) -> LoadResult<LoadedImage<Receipt>> {
    let input = request(input, backend.shared);
    let memory = backend.memory.clone();
    let mut host = Host(Rc::new(RefCell::new(backend)));
    crate::load(
        input,
        LoadServices {
            sources: &mut host.clone(),
            images: &mut host.clone(),
            memory,
            cache: &mut crate::memory::CoherentCodeCache,
            observer: &mut host.clone(),
        },
        &mut host,
    )
}
fn plan(
    input: &LoadRequest<&'static str>,
    backend: &mut Backend,
) -> LoadResult<LoadPlan<Source, Reader>> {
    let input = request(
        LoadRequest {
            source: input.source,
            profile: input.profile,
            limits: input.limits,
            role: input.role,
            namespace: NamespaceSnapshot::new(
                input.namespace.pins.clone(),
                input.namespace.global.clone(),
            )?,
        },
        backend.shared,
    );
    let mut host = Host(Rc::new(RefCell::new(backend)));
    LoadPlan::build(
        &input,
        &mut host.clone(),
        &mut host.clone(),
        &mut Vec::new(),
        &mut host,
    )
}

#[test]
fn load_observations_are_opt_in_and_complete_after_ownership_transfer() {
    for tracing in [false, true] {
        let (bytes, profile) = super::linker::native_fixture();
        let mut backend = Backend::new(alloc::vec![("root", bytes)]);
        backend.tracing = tracing;
        let loaded = load(
            LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
            &mut backend,
        )
        .expect("observing a load must not change ownership");
        let observations = backend.observations.borrow();
        if tracing {
            assert!(observations.first() == Some(&Observation::Started));
            assert!(observations.last() == Some(&Observation::Completed));
            assert!(observations.contains(&Observation::Inspected(false)));
            let phases: Vec<_> = observations
                .iter()
                .filter_map(|event| match event {
                    Observation::Phase(phase, completed) => Some((*phase, *completed)),
                    _ => None,
                })
                .collect();
            assert!(
                phases
                    == [
                        (LoadPhase::Discover, false),
                        (LoadPhase::Discover, true),
                        (LoadPhase::Acquire, false),
                        (LoadPhase::Acquire, true),
                        (LoadPhase::Map, false),
                        (LoadPhase::Map, true),
                        (LoadPhase::Link, false),
                        (LoadPhase::Link, true),
                        (LoadPhase::Publish, false),
                        (LoadPhase::Publish, true),
                    ]
            );
        } else {
            assert!(observations.is_empty());
        }
        assert_eq!(backend.commits, 1);
        drop(observations);
        drop(loaded.into_receipt());
        assert_eq!(backend.memory.releases.get(), 1);
    }
}

#[test]
fn load_failure_is_observed_after_rollback_without_a_completion() {
    for _ in 0..1 {
        let (bytes, profile) = super::linker::native_fixture();
        let mut backend = Backend::new(alloc::vec![("root", bytes)]);
        backend.tracing = true;
        backend.reject_publish = true;
        assert!(load(
            LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
            &mut backend,
        )
        .is_err());
        let observations = backend.observations.borrow();
        assert!(!observations.contains(&Observation::Completed));
        assert!(
            observations.last()
                == Some(&Observation::Failed {
                    cancels: 1,
                    // Uncommitted storage rolls back through RAII; this fixture
                    // counts only explicit release_committed calls.
                    releases: 0,
                    backings: 0,
                })
        );
    }
}

#[test]
fn load_observes_snapshot_reuse_without_reopening_the_provider() {
    let (_, profile) = super::linker::native_fixture();
    let mut provider = Backend::new(alloc::vec![("C", native_dso(&[]))]);
    provider.shared = true;
    let loaded_provider = load(
        LoadRequest::shared_object("C", profile, SessionLimits::DEFAULT),
        &mut provider,
    )
    .expect("load provider");
    let mut backend = Backend::new(alloc::vec![("root", native_dso(&["C"]))]);
    backend.shared = true;
    backend.tracing = true;
    backend.sources.push("C");
    backend.ready.push(
        loaded_provider
            .receipt()
            .pin(loaded_provider.images().next().unwrap()),
    );
    let loaded = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("reuse the published provider without its file");
    assert_eq!(backend.opens, alloc::vec!["root"]);
    let observations = backend.observations.borrow();
    assert!(observations.contains(&Observation::Inspected(true)));
    assert!(observations.contains(&Observation::Reused(b"C".to_vec())));
    assert!(observations.contains(&Observation::Dependency(b"root".to_vec(), b"C".to_vec())));
    drop(observations);
    drop(loaded);
    drop(loaded_provider);
}

#[test]
fn load_complete_entry_transfers_one_allocation() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let loaded = load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("complete load");
    let root = loaded.images().next().unwrap();
    assert_eq!(root.identity(), b"root");
    assert!(loaded.is_new(root));
    assert_eq!(loaded.lookup_scope(root).len(), 1);
    assert!(loaded.entry().unwrap().get() != 0);
    let (phdr, phent, phnum) = loaded.program_headers();
    assert_eq!(phnum, 1, "static images retain program-header geometry");
    assert_eq!(
        phent,
        match profile.class() {
            crate::profile::ElfClass::Elf32 => 32,
            crate::profile::ElfClass::Elf64 => 56,
        }
    );
    assert!(phdr.is_some());
    assert!(loaded.retained_images().is_empty());
    assert_eq!(backend.commits, 1);
    drop(loaded.into_receipt());
    assert_eq!(backend.memory.releases.get(), 1);
}

fn set_entry(bytes: &mut [u8], entry: u64) {
    if bytes[4] == 1 {
        bytes[24..28].copy_from_slice(&(entry as u32).to_le_bytes());
    } else {
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    }
}

#[test]
fn load_shared_purpose_with_entry_keeps_private_or_registry_ownership() {
    let (_, profile) = super::linker::native_fixture();
    for shared in [false, true] {
        let mut backend = Backend::new(alloc::vec![("root", native_dso(&[]))]);
        backend.shared = shared;
        let loaded = load(
            LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
            &mut backend,
        )
        .expect("a SONAME-less DSO may have a nonzero entry");
        assert_eq!(loaded.images().next().unwrap().is_shared(), shared);
        assert!(loaded.entry().is_none());
        assert_eq!(backend.commits, 1);
        drop(loaded);
        assert_eq!(backend.memory.releases.get(), 1);
    }
}

#[test]
fn load_shared_purpose_rejects_executable_roots_before_acquire() {
    let (_, profile) = super::linker::native_fixture();
    let pie = native_dso_with_flags(&[], goblin::elf::dynamic::DF_1_PIE);
    let mut exec = native_dso(&[]);
    exec[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    for shared in [false, true] {
        for bytes in [&pie, &exec] {
            let mut backend = Backend::new(alloc::vec![("root", bytes.clone())]);
            backend.shared = shared;
            let error = load(
                LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
                &mut backend,
            )
            .err()
            .expect("shared purpose rejects executables irrespective of ownership");
            assert!(matches!(error.kind(), LoadErrorKind::UnsupportedByProfile));
            assert!(!backend.memory.acquired.get());
            assert_eq!(backend.memory.allocations.get(), 0);
            assert_eq!(backend.cancels, 0);
        }
    }
}

#[test]
fn load_executable_purpose_rejects_zero_entry_and_registry_ownership() {
    let (_, profile) = super::linker::native_fixture();
    for shared in [false, true] {
        let mut bytes = native_dso(&[]);
        if !shared {
            set_entry(&mut bytes, 0);
        }
        let mut backend = Backend::new(alloc::vec![("root", bytes)]);
        backend.shared = shared;
        assert!(load(
            LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
            &mut backend,
        )
        .is_err());
        assert!(!backend.memory.acquired.get());
        assert_eq!(backend.memory.allocations.get(), 0);
    }
}

#[test]
fn load_shared_root_without_an_entry() {
    let (_, profile) = super::linker::native_fixture();
    let mut bytes = native_dso(&[]);
    set_entry(&mut bytes, 0);
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let loaded = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("shared purpose permits a zero entry");
    assert!(loaded.entry().is_none());
    assert!(loaded.startup().is_empty());
    assert_eq!(backend.memory.allocations.get(), 1);
    drop(loaded.into_receipt());
    assert_eq!(backend.memory.releases.get(), 1);
}

#[test]
fn load_segment_permission_policy_is_honored_through_sealing_and_publication() {
    use goblin::elf::program_header::{PF_R, PF_W, PF_X};

    let wx = MemoryPermissions::WRITE.bitor(MemoryPermissions::EXECUTE);
    for (flags, permissions) in [
        (PF_W | PF_X, wx),
        (PF_R | PF_W | PF_X, wx.bitor(MemoryPermissions::READ)),
    ] {
        for allowed in [false, true] {
            let (mut bytes, base) = super::linker::native_fixture();
            let flags_offset = if bytes[4] == 1 { 52 + 24 } else { 64 + 4 };
            bytes[flags_offset..flags_offset + 4].copy_from_slice(&flags.to_le_bytes());
            let profile = base.with_segment_permission_policy(
                base.segment_permission_policy()
                    .with_permissions(permissions, allowed),
            );
            let mut backend = Backend::new(alloc::vec![("root", bytes)]);
            let result = load(
                LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
                &mut backend,
            );
            if allowed {
                let loaded = result.expect("configured permissions must survive sealing");
                assert!(loaded.entry().is_some());
                assert_eq!(backend.commits, 1);
                assert_eq!(backend.memory.allocations.get(), 1);
                drop(loaded.into_receipt());
                assert_eq!(backend.memory.releases.get(), 1);
            } else {
                let error = result.err().expect("default policy rejects W+X");
                assert_eq!(error.kind(), LoadErrorKind::PermissionConflict);
                assert_eq!(backend.commits, 0);
                assert_eq!(backend.memory.allocations.get(), 0);
            }
        }
    }
}

#[test]
fn load_marked_pie_requires_an_executable_entry() {
    let (_, profile) = super::linker::native_fixture();
    let mut bytes = native_dso_with_flags(&[], goblin::elf::dynamic::DF_1_PIE);
    set_entry(&mut bytes, 0);
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    assert!(load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(backend.commits, 0);
}

#[test]
fn load_executable_uses_elf_fixed_placement() {
    use crate::memory::{AllocationOwnership, MemoryRegion};
    use blueos_infra::storage::Storage;
    let backing = Storage::try_from_layout(core::alloc::Layout::from_size_align(0x100, 4).unwrap())
        .expect("fixed test backing");
    let base = backing.base() as usize;
    let (mut bytes, profile) = super::linker::native_fixture();
    bytes[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    if bytes[4] == 1 {
        bytes[60..64].copy_from_slice(&(base as u32).to_le_bytes());
        bytes[64..68].copy_from_slice(&(base as u32).to_le_bytes());
    } else {
        bytes[80..88].copy_from_slice(&(base as u64).to_le_bytes());
        bytes[88..96].copy_from_slice(&(base as u64).to_le_bytes());
    }
    set_entry(
        &mut bytes,
        base as u64 | u64::from(profile.entry_mode().is_thumb()),
    );
    let regions = alloc::boxed::Box::leak(alloc::boxed::Box::new([unsafe {
        // The test owns this backing until its receipt and backend are gone.
        MemoryRegion::new(
            base,
            base + 0x100,
            MemoryPermissions::READ
                .bitor(MemoryPermissions::WRITE)
                .bitor(MemoryPermissions::EXECUTE),
        )
    }]));
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.memory.regions = Some(regions);
    let mut loaded = load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("ET_EXEC uses the same public load entry");
    assert_eq!(
        loaded.entry().unwrap().get(),
        base as u64 | u64::from(profile.entry_mode().is_thumb())
    );
    assert_eq!(
        loaded.receipt_mut().leases[0].allocation().ownership(),
        AllocationOwnership::BorrowedFixed
    );
    drop(loaded.into_receipt());
    assert_eq!(backend.memory.releases.get(), 1);
    drop(backend);
    drop(backing);
}

#[test]
fn load_fixed_exec_rejects_unreserved_addresses() {
    let (mut bytes, profile) = super::linker::native_fixture();
    bytes[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let error = load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .err()
    .expect("fixed placement requires platform permission");
    assert!(matches!(error.kind(), LoadErrorKind::OutOfBounds));
    assert_eq!(backend.commits, 0);
}

#[test]
fn load_rejects_executable_dependencies_before_mapping() {
    let mut dependency = dso_elf(&[], None);
    dependency[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left"], None)),
        ("left", dependency),
    ]);
    let error = load(plan_request(SessionLimits::DEFAULT), &mut backend)
        .err()
        .expect("a dependency must be a shared object");
    assert!(matches!(error.kind(), LoadErrorKind::UnsupportedByProfile));
    assert!(!backend.memory.acquired.get());
    assert_eq!(backend.memory.allocations.get(), 0);
}
#[test]
fn dropping_prepared_load_rolls_back_without_commit() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let input = request(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        false,
    );
    let memory = backend.memory.clone();
    let host = Host(Rc::new(RefCell::new(&mut backend)));
    let prepared = crate::prepare_load(
        input,
        LoadServices {
            sources: &mut host.clone(),
            images: &mut host.clone(),
            memory,
            cache: &mut crate::memory::CoherentCodeCache,
            observer: &mut host.clone(),
        },
    )
    .unwrap();
    assert_eq!(prepared.manifest().allocations().len(), 1);
    drop(prepared);
    drop(host);
    assert!(backend.memory.mappers.borrow().is_empty());
    assert_eq!(backend.commits, 0);
    assert_eq!(backend.cancels, 1);
}
#[test]
fn load_publication_failure_aborts_before_commit() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.reject_publish = true;
    assert!(load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(
        (backend.commits, backend.aborts, backend.cancels),
        (0, 0, 1)
    );
    backend.reject_publish = false;
    let loaded = load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("rollback freed mapper");
    drop(loaded.into_receipt());
}
#[test]
fn load_acquire_failure_maps_no_images() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.reject_acquire = true;
    assert!(load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(backend.memory.allocations.get(), 0);
    assert_eq!(backend.cancels, 0);
}

// Reusing a provider must preserve dependencies beneath it without mapping
// either provider again, and expose that closure to dlsym and retention.
#[test]
fn load_reused_provider_preserves_transitive_closure() {
    let (_, profile) = super::linker::native_fixture();
    let c_bytes = native_dso(&[]);
    let b_bytes = native_dso(&["C"]);
    let root_bytes = native_dso(&["B"]);
    let mut c_backend = Backend::new(alloc::vec![("C", c_bytes.clone())]);
    let c = load(
        LoadRequest::shared_object("C", profile, SessionLimits::DEFAULT),
        &mut c_backend,
    )
    .expect("load C");
    let c_handle = c.images().next().unwrap().clone();
    let mut b_backend = Backend::new(alloc::vec![("B", b_bytes.clone()), ("C", c_bytes.clone())]);
    let b_request = LoadRequest::shared_object("B", profile, SessionLimits::DEFAULT)
        .with_namespace(namespace(
            alloc::vec![c.receipt().pin(&c_handle)],
            Vec::new(),
        ));
    let b = load(b_request, &mut b_backend).expect("load B with existing C");
    let b_handle = b.images().next().unwrap().clone();
    assert_eq!(b_handle.dependencies().len(), 1);
    assert_eq!(b_handle.dependencies()[0].name(), b"C");
    assert_eq!(b_handle.dependencies()[0].identity(), b"C");
    assert!(!b_handle.dependencies()[0].is_shared());
    for replacement in [None, Some(alloc::vec![0; 16]), Some(native_dso(&["new"]))] {
        let mut backend = Backend::new(alloc::vec![
            ("root", root_bytes.clone()),
            ("B", b_bytes.clone()),
            ("C", c_bytes.clone())
        ]);
        backend.files.retain(|(source, _)| *source == "root");
        if let Some(bytes) = replacement {
            backend.files.push(("B", Rc::from(bytes)));
        }
        let request = LoadRequest::executable("root", profile, planning_limits(64, 2))
            .with_namespace(namespace(
                alloc::vec![b.receipt().pin(&b_handle), c.receipt().pin(&c_handle)],
                Vec::new(),
            ));
        let loaded =
            load(request, &mut backend).expect("reuse original B -> C despite filesystem changes");
        let root = loaded.images().next().unwrap();
        assert_eq!(
            loaded
                .lookup_scope(root)
                .iter()
                .map(|image| image.identity())
                .collect::<Vec<_>>(),
            [b"root".as_slice(), b"B".as_slice(), b"C".as_slice()]
        );
        assert_eq!(backend.opens, ["root"]);
        assert_eq!(loaded.retained_images().len(), 2);
        assert_eq!(backend.memory.allocations.get(), 1);
        drop(loaded.into_receipt());
    }
    drop(b.into_receipt());
    drop(c.into_receipt());
}

#[test]
fn load_ready_cycle_uses_snapshots_without_elf_files() {
    let (_, profile) = super::linker::native_fixture();
    let mut owner = Backend::new(alloc::vec![
        ("root", native_dso(&["child"])),
        ("child", native_dso(&["root"]))
    ]);
    owner.shared = true;
    let original = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
        &mut owner,
    )
    .unwrap();
    let mut backend = Backend::new(alloc::vec![("root", Vec::new()), ("child", Vec::new())]);
    backend.shared = true;
    backend.ready = original
        .images()
        .map(|i| original.receipt().pin(i))
        .collect();
    backend.files.clear();
    let reused = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .unwrap();
    let root = reused.images().next().unwrap();
    assert!(!reused.is_new(root));
    assert_eq!(reused.lookup_scope(root).len(), 2);
    assert!(reused.entry().is_none());
    assert!(reused.startup().is_empty());
    assert!(backend.opens.is_empty());
    assert_eq!(backend.memory.allocations.get(), 0);
    assert_eq!(root.dependencies()[0].identity(), b"child");
    assert!(root.dependencies()[0].is_shared());
}

#[test]
fn load_snapshot_requires_its_original_loaded_dependency() {
    let (_, profile) = super::linker::native_fixture();
    let mut owner = Backend::new(alloc::vec![
        ("B", native_dso(&["C"])),
        ("C", native_dso(&[]))
    ]);
    let original = load(
        LoadRequest::shared_object("B", profile, SessionLimits::DEFAULT),
        &mut owner,
    )
    .unwrap();
    let mut backend = Backend::new(alloc::vec![("B", native_dso(&[])), ("C", native_dso(&[]))]);
    backend
        .ready
        .push(original.receipt().pin(original.images().next().unwrap()));
    assert!(load(
        LoadRequest::shared_object("B", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert!(
        backend.opens.is_empty(),
        "a missing pin must not reload an old provider's file"
    );
    assert!(!backend.memory.acquired.get());
}

#[test]
fn load_snapshot_rejects_incompatible_profile_and_executable_role() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut owner = Backend::new(alloc::vec![("root", bytes)]);
    let executable = load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
        &mut owner,
    )
    .unwrap();
    for requested_profile in [
        profile,
        if profile == LoadProfile::riscv64() {
            LoadProfile::aarch64()
        } else {
            LoadProfile::riscv64()
        },
    ] {
        let mut backend = Backend::new(alloc::vec![("root", Vec::new())]);
        backend.ready = executable
            .images()
            .map(|i| executable.receipt().pin(i))
            .collect();
        let error = load(
            LoadRequest::shared_object("root", requested_profile, SessionLimits::DEFAULT),
            &mut backend,
        )
        .err()
        .unwrap();
        assert!(matches!(error.kind(), LoadErrorKind::UnsupportedByProfile));
        assert!(backend.opens.is_empty());
        assert!(!backend.memory.acquired.get());
    }
}

#[test]
fn load_concurrent_ready_provider_replans_its_frozen_closure() {
    let (_, profile) = super::linker::native_fixture();
    let mut owner = Backend::new(alloc::vec![
        ("B", native_dso(&["C"])),
        ("C", native_dso(&[]))
    ]);
    owner.shared = true;
    let original = load(
        LoadRequest::shared_object("B", profile, SessionLimits::DEFAULT),
        &mut owner,
    )
    .unwrap();
    let mut backend = Backend::new(alloc::vec![
        ("root", native_dso(&["B"])),
        ("B", native_dso(&["D"])),
        ("D", native_dso(&[])),
        ("C", Vec::new())
    ]);
    backend.shared = true;
    backend.ready_after_acquire = original
        .images()
        .map(|i| original.receipt().pin(i))
        .collect();
    backend.tracing = true;
    backend.files.retain(|(source, _)| *source != "C");
    let loaded = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .unwrap();
    let root = loaded.images().next().unwrap();
    assert_eq!(
        loaded
            .lookup_scope(root)
            .iter()
            .map(|image| image.identity())
            .collect::<Vec<_>>(),
        [b"root".as_slice(), b"B".as_slice(), b"C".as_slice()]
    );
    assert_eq!(
        backend.cancels, 1,
        "cancel the obsolete reservation before replanning"
    );
    assert_eq!(backend.memory.allocations.get(), 1);
    assert_eq!(backend.opens, ["root", "B", "D", "root"]);
    assert!(backend
        .observations
        .borrow()
        .contains(&Observation::Retry(1)));
}

#[test]
fn a_retained_namespace_pin_outlives_the_original_owner() {
    let (_, profile) = super::linker::native_fixture();
    let mut owner = Backend::new(alloc::vec![("C", native_dso(&[]))]);
    let c = load(
        LoadRequest::shared_object("C", profile, SessionLimits::DEFAULT),
        &mut owner,
    )
    .unwrap();
    let handle = c.images().next().unwrap().clone();
    let pin = c.receipt().pin(&handle);
    drop(c);
    assert_eq!(owner.memory.releases.get(), 0);
    let mut consumer = Backend::new(alloc::vec![("root", native_dso(&["C"]))]);
    consumer.sources.push("C");
    let image = load(
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT)
            .with_namespace(namespace(alloc::vec![pin], Vec::new())),
        &mut consumer,
    )
    .unwrap();
    assert_eq!(owner.memory.releases.get(), 0);
    assert_eq!(
        image.retained_images()[0].instance_id(),
        handle.instance_id()
    );
    drop(image);
    assert_eq!(owner.memory.releases.get(), 1);
}

#[test]
fn frozen_dependencies_reject_a_replacement_generation_at_the_same_key() {
    let (_, profile) = super::linker::native_fixture();
    let mut first = Backend::new(alloc::vec![("C", native_dso(&[]))]);
    let c = load(
        LoadRequest::shared_object("C", profile, SessionLimits::DEFAULT),
        &mut first,
    )
    .unwrap();
    let mut b_backend = Backend::new(alloc::vec![("B", native_dso(&["C"]))]);
    b_backend.sources.push("C");
    let b = load(
        LoadRequest::shared_object("B", profile, SessionLimits::DEFAULT).with_namespace(namespace(
            alloc::vec![c.receipt().pin(c.images().next().unwrap())],
            Vec::new(),
        )),
        &mut b_backend,
    )
    .unwrap();
    let mut replacement = Backend::new(alloc::vec![("C", native_dso(&[]))]);
    let new_c = load(
        LoadRequest::shared_object("C", profile, SessionLimits::DEFAULT),
        &mut replacement,
    )
    .unwrap();
    assert_ne!(
        c.images().next().unwrap().instance_id(),
        new_c.images().next().unwrap().instance_id()
    );
    let mut root = Backend::new(alloc::vec![("root", native_dso(&["B"]))]);
    root.sources.push("B");
    root.ready.push(c.receipt().pin(c.images().next().unwrap()));
    let request =
        LoadRequest::executable("root", profile, SessionLimits::DEFAULT).with_namespace(namespace(
            alloc::vec![
                b.receipt().pin(b.images().next().unwrap()),
                new_c.receipt().pin(new_c.images().next().unwrap())
            ],
            Vec::new(),
        ));
    assert!(load(request, &mut root).is_err());
    assert_eq!(root.memory.allocations.get(), 0);
    assert_eq!(root.opens, ["root"]);
}

#[test]
fn invalid_repository_batches_reject_before_mapping_and_cancel_once() {
    let (_, profile) = super::linker::native_fixture();
    for malformed in 1..=4 {
        let mut backend = Backend::new(alloc::vec![
            ("root", native_dso(&["child"])),
            ("child", native_dso(&[]))
        ]);
        backend.malformed_reservation = malformed;
        assert!(load(
            LoadRequest::executable("root", profile, SessionLimits::DEFAULT),
            &mut backend
        )
        .is_err());
        assert_eq!(backend.cancels, 1);
        assert_eq!(backend.memory.allocations.get(), 0);
        assert_eq!(backend.commits, 0);
    }
}

fn native_dso(needed: &[&str]) -> Vec<u8> {
    native_dso_with_flags(needed, 0)
}

fn native_dso_with_flags(needed: &[&str], dynamic_flags: u64) -> Vec<u8> {
    native_dso_with_symbols(needed, dynamic_flags, &[], None)
}

// Absolute exports and one real symbolic data relocation allow retention
// tests to exercise provider selection through the complete public load API.
fn native_dso_with_symbols(
    needed: &[&str],
    dynamic_flags: u64,
    symbols: &[(&str, bool)],
    relocation: Option<usize>,
) -> Vec<u8> {
    use super::fixture::ElfFixtureBuilder;
    use goblin::elf::{
        dynamic::{
            DT_FLAGS_1, DT_HASH, DT_NEEDED, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT,
            DT_RELSZ, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB,
        },
        header::*,
    };
    #[cfg(target_arch = "arm")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf32(EM_ARM, ET_DYN),
        0x0500_0200,
        0x1001,
        52,
        32,
    );
    #[cfg(target_arch = "riscv32")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf32(EM_RISCV, ET_DYN),
        0,
        0x1000,
        52,
        32,
    );
    #[cfg(target_arch = "riscv64")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN),
        0,
        0x1000,
        64,
        56,
    );
    #[cfg(target_arch = "aarch64")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf64(EM_AARCH64, ET_DYN),
        0,
        0x1000,
        64,
        56,
    );
    let mut names = alloc::vec![0];
    let mut entries = Vec::new();
    for name in needed {
        entries.push((DT_NEEDED as u32, names.len() as u64));
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let mut symbol_offsets = Vec::new();
    for (name, _) in symbols {
        symbol_offsets.push(names.len());
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    entries.push((DT_FLAGS_1 as u32, dynamic_flags));
    entries.push((DT_SYMTAB as u32, 0x1180));
    entries.push((DT_SYMENT as u32, if header == 52 { 16 } else { 24 }));
    entries.push((DT_HASH as u32, 0x1240));
    entries.push((DT_STRTAB as u32, 0x1300));
    entries.push((DT_STRSZ as u32, names.len() as u64));
    let rel = cfg!(target_arch = "arm");
    let rel_size = if rel {
        8
    } else if header == 52 {
        12
    } else {
        24
    };
    if relocation.is_some() {
        entries.push((if rel { DT_REL } else { DT_RELA } as u32, 0x1280));
        entries.push((if rel { DT_RELSZ } else { DT_RELASZ } as u32, rel_size));
        entries.push((if rel { DT_RELENT } else { DT_RELAENT } as u32, rel_size));
    }
    let mut bytes = builder
        .with_flags(flags)
        .with_load_segment(0x1000, 0x400, 0x400, 4)
        .with_entry(entry)
        .with_dynamic_entries(0x1000 + 2 * phdr, &entries)
        .with_dynstr(header + 0x300, &names)
        .build();
    let mut hash = alloc::vec![
        1u32,
        (symbols.len() + 1) as u32,
        u32::from(!symbols.is_empty()),
        0
    ];
    for index in 1..=symbols.len() {
        hash.push(if index < symbols.len() {
            index as u32 + 1
        } else {
            0
        });
    }
    for (index, word) in hash.into_iter().enumerate() {
        let at = header + 0x240 + index * 4;
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    for (index, ((_, defined), name)) in symbols.iter().zip(symbol_offsets).enumerate() {
        let size = if header == 52 { 16 } else { 24 };
        let at = header + 0x180 + (index + 1) * size;
        bytes[at..at + 4].copy_from_slice(&(name as u32).to_le_bytes());
        let section = if *defined { 0xfff1u16 } else { 0 };
        if header == 52 {
            bytes[at + 4..at + 8].copy_from_slice(&0x1234u32.to_le_bytes());
            bytes[at + 12] = 0x10; // STB_GLOBAL, STT_NOTYPE
            bytes[at + 14..at + 16].copy_from_slice(&section.to_le_bytes());
        } else {
            bytes[at + 4] = 0x10;
            bytes[at + 6..at + 8].copy_from_slice(&section.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&0x1234u64.to_le_bytes());
        }
    }
    if let Some(symbol) = relocation {
        let at = header + 0x280;
        let kind = if rel {
            2
        } else if cfg!(target_arch = "aarch64") {
            257
        } else if header == 52 {
            1
        } else {
            2
        };
        if header == 52 {
            bytes[at..at + 4].copy_from_slice(&0x13c0u32.to_le_bytes());
            bytes[at + 4..at + 8]
                .copy_from_slice(&(((symbol as u32 + 1) << 8) | kind).to_le_bytes());
        } else {
            bytes[at..at + 8].copy_from_slice(&0x13c0u64.to_le_bytes());
            bytes[at + 8..at + 16]
                .copy_from_slice(&(((symbol as u64 + 1) << 32) | u64::from(kind)).to_le_bytes());
        }
        // This shared fixture has only data and no executable entry.
        set_entry(&mut bytes, 0);
        let flags_at = if header == 52 {
            header + 24
        } else {
            header + 4
        };
        bytes[flags_at..flags_at + 4].copy_from_slice(&6u32.to_le_bytes());
    }
    bytes
}

#[test]
fn shared_image_retains_an_actual_global_provider_without_dt_needed() {
    let (_, profile) = super::linker::native_fixture();
    let mut provider_backend = Backend::new(alloc::vec![(
        "provider",
        native_dso_with_symbols(&[], 0, &[("probe", true)], None)
    )]);
    provider_backend.shared = true;
    let provider = load(
        LoadRequest::shared_object("provider", profile, SessionLimits::DEFAULT),
        &mut provider_backend,
    )
    .unwrap();
    let provider_handle = provider.images().next().unwrap().clone();
    let mut backend = Backend::new(alloc::vec![(
        "root",
        native_dso_with_symbols(&[], 0, &[("probe", false)], Some(0))
    )]);
    backend.shared = true;
    let mut image = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT).with_namespace(
            namespace(
                alloc::vec![provider.receipt().pin(&provider_handle)],
                alloc::vec![provider_handle],
            ),
        ),
        &mut backend,
    )
    .unwrap();
    let root = image.images().next().unwrap();
    assert_eq!(
        image.lookup_scope(root).len(),
        1,
        "provider is outside DT_NEEDED"
    );
    assert_eq!(
        image
            .shared_dependencies(root)
            .iter()
            .map(ImageHandle::identity)
            .collect::<Vec<_>>(),
        [b"provider".as_slice()]
    );
    assert_eq!(image.retained_images().len(), 1);
    let mut value = [0u8; 8];
    let word_size = if profile.class() == crate::profile::ElfClass::Elf32 {
        4
    } else {
        8
    };
    backend
        .memory
        .read(
            image.receipt_mut().leases[0].allocation(),
            AllocationOffset::new(0x3c0),
            &mut value[..word_size],
        )
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(value),
        0x1234,
        "the relocation used the retained export"
    );
}

#[test]
fn shared_binding_cycle_is_structural_and_preserves_reverse_lifecycle_order() {
    let (_, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![
        (
            "root",
            native_dso_with_symbols(&["child"], 0, &[("a", true), ("b", false)], Some(1))
        ),
        (
            "child",
            native_dso_with_symbols(&[], 0, &[("b", true), ("a", false)], Some(1))
        ),
    ]);
    backend.shared = true;
    let image = load(
        LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .unwrap();
    for member in image.images() {
        assert_eq!(
            image
                .shared_component(member)
                .iter()
                .map(ImageHandle::identity)
                .collect::<Vec<_>>(),
            [b"root".as_slice(), b"child".as_slice()]
        );
        assert!(
            image.shared_dependencies(member).is_empty(),
            "internal binding edges must not pin the cycle"
        );
    }
}

fn plan_request(limits: SessionLimits) -> LoadRequest<&'static str> {
    LoadRequest::shared_object("root", LoadProfile::arm_thumb_soft_float(), limits)
}

fn planning_limits(images: u32, depth: u16) -> SessionLimits {
    SessionLimits::new(
        LoadLimits::DEFAULT,
        images,
        1024,
        depth,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        256,
        256,
    )
}

#[test]
fn load_accepts_exact_dependency_depth_limits() {
    let (_, profile) = super::linker::native_fixture();
    for depth in 0..=2u16 {
        let files = match depth {
            0 => alloc::vec![("root", native_dso(&[]))],
            1 => alloc::vec![("root", native_dso(&["left"])), ("left", native_dso(&[])),],
            _ => alloc::vec![
                ("root", native_dso(&["left"])),
                ("left", native_dso(&["leaf"])),
                ("leaf", native_dso(&[])),
            ],
        };
        let mut backend = Backend::new(files);
        let image = load(
            LoadRequest::shared_object("root", profile, planning_limits(64, depth)),
            &mut backend,
        )
        .expect("closure ends exactly at the depth limit");
        let count = usize::from(depth.saturating_add(1));
        assert_eq!(image.images().count(), count);
        assert_eq!(backend.commits, 1);
        drop(image.into_receipt());
        assert_eq!(backend.memory.releases.get(), count);
    }
}

#[test]
fn planning_rejects_the_first_dependency_beyond_the_depth_limit() {
    for depth in 0..=1u16 {
        let mut backend = Backend::new(alloc::vec![
            ("root", dso_elf(&["left"], None)),
            ("left", dso_elf(&["leaf"], None)),
            ("leaf", dso_elf(&[], None)),
        ]);
        let error = plan(&plan_request(planning_limits(64, depth)), &mut backend)
            .err()
            .expect("next dependency exceeds the depth limit");
        assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
        assert!(matches!(
            error.context(),
            ErrorContext::Limit {
                resource: LimitKind::DependencyDepth,
                actual,
                maximum,
            } if *actual == u64::from(depth.saturating_add(1))
                && *maximum == u64::from(depth)
        ));
        assert_eq!(backend.memory.allocations.get(), 0);
        assert!(!backend.memory.acquired.get());
    }
}

#[test]
fn planning_closes_diamond_and_cycle_in_bfs_order() {
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left", "right", "left"], None)),
        ("left", dso_elf(&["leaf"], None)),
        ("right", dso_elf(&["leaf"], None)),
        ("leaf", dso_elf(&["left"], None)),
    ]);
    let plan = plan(&plan_request(planning_limits(64, 2)), &mut backend)
        .expect("diamond and cycle fit at depth two");
    assert_eq!(
        plan.images
            .iter()
            .map(|image| image.source.as_ref().unwrap().name)
            .collect::<Vec<_>>(),
        ["root", "left", "right", "leaf"]
    );
    assert_eq!(plan.edges.len(), 6);
    assert_eq!(plan.edges[0].provider, plan.edges[2].provider);
    assert_eq!(plan.edges[3].provider, plan.edges[4].provider);
    assert_eq!(backend.memory.allocations.get(), 0);
}
#[test]
fn planning_enforces_image_and_depth_limits_before_mapping() {
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left"], None)),
        ("left", dso_elf(&["leaf"], None)),
        ("leaf", dso_elf(&[], None))
    ]);
    for (images, depth) in [(2, 32), (64, 1)] {
        let limits = planning_limits(images, depth);
        let error = plan(&plan_request(limits), &mut backend)
            .err()
            .expect("bounded plan");
        assert!(matches!(error.kind(), LoadErrorKind::ResourceLimit));
        assert!(matches!(
            (images, error.context()),
            (
                2,
                ErrorContext::Limit {
                    resource: LimitKind::ImageCount,
                    actual: 3,
                    maximum: 2,
                }
            ) | (
                64,
                ErrorContext::Limit {
                    resource: LimitKind::DependencyDepth,
                    actual: 2,
                    maximum: 1,
                }
            )
        ));
    }
    assert_eq!(backend.memory.allocations.get(), 0);
}

#[test]
fn mapping_rejects_changed_dependency_names_order_and_count() {
    let (_, profile) = super::linker::native_fixture();
    for changed in [&["C", "B"][..], &["B"][..], &["B", "C", "D"][..]] {
        let mut backend = Backend::new(alloc::vec![
            ("root", native_dso(&["B", "C"])),
            ("B", native_dso(&[])),
            ("C", native_dso(&[])),
            ("D", native_dso(&[])),
        ]);
        let request = LoadRequest::shared_object("root", profile, SessionLimits::DEFAULT);
        let mut plan = plan(&request, &mut backend).unwrap();
        // Model a file changing between scanning and mapping. No newly declared
        // dependency may escape the closure that was acquired from the scan.
        plan.images[0].reader = Some(Reader(Rc::from(native_dso(changed))));
        backend.memory.acquired.set(true);
        let mut memory = backend.memory.clone();
        let error = crate::loading::materialize::load_images(
            &mut plan,
            &[],
            &[],
            profile,
            SessionLimits::DEFAULT,
            &mut memory,
            |_| {},
        )
        .err()
        .expect("mapped dependency list disagrees with the acquired plan");
        assert!(matches!(error.kind(), LoadErrorKind::BadElf));
        assert_eq!(backend.memory.allocations.get(), 1);
        assert!(backend.memory.mappers.borrow().is_empty());
        assert_eq!(backend.commits, 0);
    }
}
#[test]
fn load_request_discovers_declared_dependencies() {
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left"], None)),
        ("left", dso_elf(&[], None)),
    ]);
    let plan = plan(&plan_request(SessionLimits::DEFAULT), &mut backend)
        .expect("dependencies are inferred from DT_NEEDED");
    assert_eq!(plan.images.len(), 2);
    assert_eq!(plan.edges.len(), 1);
    assert!(!backend.memory.acquired.get());
}

fn dso_elf(needed: &[&str], soname: Option<&str>) -> Vec<u8> {
    // dynstr: NUL-joined names, prefixed by a 1-byte padding NUL so
    // every name offset is >= 1 (offset 0 would be an empty name).
    let mut dynstr: Vec<u8> = alloc::vec![0];
    let mut offsets = Vec::new();
    for name in needed.iter().chain(soname.iter()) {
        offsets.push(dynstr.len());
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
    }
    // The dynstr's vaddr: the PT_LOAD maps file offset `str_off` at
    // vaddr 0x1000 + str_off. Two name-position entries always come
    // first, so dyn_len (and thus str_off) is computable up front.
    let dyn_len = (2 + needed.len() + usize::from(soname.is_some()) + 1) * 8;
    let str_off = DYN_OFF + dyn_len;
    let strsz = dynstr.len();
    let mut entries: Vec<(u32, u64)> = alloc::vec![
        (DT_STRTAB, 0x1000 + str_off as u64),
        (DT_STRSZ, strsz as u64),
    ];
    for &offset in &offsets[..needed.len()] {
        entries.push((DT_NEEDED, offset as u64));
    }
    if soname.is_some() {
        entries.push((DT_SONAME, offsets[needed.len()] as u64));
    }

    let mut bytes = alloc::vec![0u8; str_off + strsz];
    // ehdr
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELFCLASS32
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&(ET_DYN as u16).to_le_bytes()); // e_type
    bytes[18..20].copy_from_slice(&(EM_ARM as u16).to_le_bytes()); // e_machine
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    bytes[28..32].copy_from_slice(&(ELF32_EHDR_SIZE as u32).to_le_bytes()); // e_phoff

    // e_flags: EABI5 | EF_ARM_ABI_FLOAT_SOFT, as required by the
    // arm_thumb_soft_float profile.
    bytes[36..40].copy_from_slice(&0x0500_0200u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&(ELF32_EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
    bytes[42..44].copy_from_slice(&(32u16).to_le_bytes()); // e_phentsize
    bytes[44..46].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    // PT_LOAD: r-x, covering the whole file at vaddr 0x1000. ELF32 phdr
    // field order: type, offset, vaddr, paddr, filesz, memsz, flags, align.
    let ph0 = ELF32_EHDR_SIZE;
    let file_len = bytes.len() as u32;
    bytes[ph0..ph0 + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes[ph0 + 4..ph0 + 8].copy_from_slice(&0u32.to_le_bytes()); // p_offset
    bytes[ph0 + 8..ph0 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // p_vaddr
    bytes[ph0 + 12..ph0 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // p_paddr
    bytes[ph0 + 16..ph0 + 20].copy_from_slice(&file_len.to_le_bytes()); // p_filesz
    bytes[ph0 + 20..ph0 + 24].copy_from_slice(&file_len.to_le_bytes()); // p_memsz
    bytes[ph0 + 24..ph0 + 28].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes[ph0 + 28..ph0 + 32].copy_from_slice(&4u32.to_le_bytes()); // p_align

    // PT_DYNAMIC uses the same ELF32 field order.
    let ph1 = ph0 + 32;
    bytes[ph1..ph1 + 4].copy_from_slice(&2u32.to_le_bytes()); // p_type = PT_DYNAMIC
    bytes[ph1 + 4..ph1 + 8].copy_from_slice(&(DYN_OFF as u32).to_le_bytes()); // p_offset
    bytes[ph1 + 8..ph1 + 12].copy_from_slice(&(0x1000 + DYN_OFF as u32).to_le_bytes()); // p_vaddr
    bytes[ph1 + 12..ph1 + 16].copy_from_slice(&(DYN_OFF as u32).to_le_bytes()); // p_paddr
    bytes[ph1 + 16..ph1 + 20].copy_from_slice(&(dyn_len as u32).to_le_bytes()); // p_filesz
    bytes[ph1 + 20..ph1 + 24].copy_from_slice(&(dyn_len as u32).to_le_bytes()); // p_memsz
    bytes[ph1 + 24..ph1 + 28].copy_from_slice(&4u32.to_le_bytes()); // p_flags = R
    bytes[ph1 + 28..ph1 + 32].copy_from_slice(&4u32.to_le_bytes()); // p_align
                                                                    // dynamic entries
    for (index, &(tag, value)) in entries.iter().enumerate() {
        let at = DYN_OFF + index * 8;
        bytes[at..at + 4].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&(value as u32).to_le_bytes());
    }
    // dynstr
    bytes[str_off..str_off + strsz].copy_from_slice(&dynstr);
    bytes
}

const DYN_OFF: usize = 52 + 2 * 32;
const ELF32_EHDR_SIZE: usize = 52;
const ET_DYN: u16 = 3;
const EM_ARM: u16 = 40;
const DT_STRTAB: u32 = 5;
const DT_STRSZ: u32 = 10;
const DT_NEEDED: u32 = 1;
const DT_SONAME: u32 = 14;
