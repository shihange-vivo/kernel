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

//! Thread-group resources, membership and cooperative main-thread exit.
//! `CONFIG_THREAD_GROUP=y` selects this model instead of `crate::process`.
//! It is independent of ELF architecture support and optional VFS services.
//! Registered members retain their group; retirement callbacks hold weak handles.
//! ThreadGroupInner therefore survives a dropped ThreadGroup without an Arc cycle.

use crate::{
    scheduler,
    support::DisableInterruptGuard,
    sync::SpinLock,
    thread::{self, CleanupError, DeferredCleanup, GlobalQueueVisitor, Thread, ThreadNode},
    time::Tick,
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

#[cfg(all(loader_backend, enable_dynamic_linker, enable_vfs))]
use crate::loader::{LinkerAccess, LinkerRuntime};

#[cfg(enable_vfs)]
mod files;
#[cfg(enable_vfs)]
pub use files::StandardIo;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadGroupState {
    Prepared,
    Running,
    Exiting,
    Exited,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadGroupExit {
    /// Main return or exit completed libc finalization before retirement.
    Code(i32),
    /// Startup was cancelled or main retired without completing finalization.
    Aborted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadGroupError {
    AlreadyStarted,
    NotStarted,
    QueueFailed,
}

/// Observe and start a thread group. Dropping a prepared handle cancels startup;
/// dropping a running handle leaves its members owning the image through exit.
#[must_use = "start the thread group or drop it to cancel its prepared resources"]
pub struct ThreadGroup {
    group: Arc<ThreadGroupInner>,
}

/// Shared group lifetime, retained by registered members independently of
/// the public ThreadGroup handle. Retirement callbacks only hold weak references.
#[must_use = "retain group resources until all member cleanups finish"]
pub(crate) struct ThreadGroupInner {
    // Keep the main thread and its startup stack through every member cleanup,
    // and through wait() while the public observer still retains this group.
    main_thread: ThreadNode,
    state: SpinLock<GroupState>,
    #[cfg(enable_vfs)]
    files: files::ThreadGroupFiles,
    // Only the last member takes the owner, outside the state lock.
    image_owner: Mutex<Option<ImageOwner>>,
    changed: AtomicUsize,
}

#[must_use = "retain the image and its startup data through group cleanup"]
struct ImageOwner {
    _startup: Box<dyn Send>,
    #[cfg(all(loader_backend, enable_dynamic_linker, enable_vfs))]
    linker: LinkerSlot,
}

#[cfg(all(loader_backend, enable_dynamic_linker, enable_vfs))]
#[must_use = "retain the group linker runtime through cleanup"]
enum LinkerSlot {
    Unavailable,
    Ready(Box<LinkerRuntime>),
    Busy,
}

/// Membership and exit progress coordinated by one state lock.
#[must_use = "retain member threads until group cleanup"]
struct GroupState {
    phase: ThreadGroupState,
    exit_code: Option<i32>,
    fini_complete: bool,
    outcome: Option<ThreadGroupExit>,
    // Includes retired threads until their deferred cleanup completes.
    members: Vec<ThreadNode>,
}

// Each registered thread retains its group until its deferred cleanup finishes.
static MEMBERS: SpinLock<BTreeMap<usize, Arc<ThreadGroupInner>>> = SpinLock::new(BTreeMap::new());

impl ThreadGroup {
    /// Take ownership of an unscheduled main thread and its image resources.
    /// A failed cleanup preparation removes the thread's global registration
    /// before releasing its stack or image in the caller's context.
    pub(crate) fn prepare(
        mut main_thread: ThreadNode,
        image_owner: Box<dyn Send>,
        #[cfg(enable_vfs)] table: crate::vfs::fd_manager::FdManager,
    ) -> Result<Self, CleanupError> {
        let group = Arc::new(ThreadGroupInner {
            main_thread: main_thread.clone(),
            state: SpinLock::new(GroupState {
                phase: ThreadGroupState::Prepared,
                exit_code: None,
                fini_complete: false,
                outcome: None,
                members: vec![main_thread.clone()],
            }),
            #[cfg(enable_vfs)]
            files: files::ThreadGroupFiles::new(table),
            image_owner: Mutex::new(Some(ImageOwner {
                _startup: image_owner,
                #[cfg(all(loader_backend, enable_dynamic_linker, enable_vfs))]
                linker: LinkerSlot::Unavailable,
            })),
            changed: AtomicUsize::new(0),
        });
        let weak = Arc::downgrade(&group);
        let cleanup = match DeferredCleanup::new(move || {
            if let Some(group) = weak.upgrade() {
                group.finish(Thread::id(&group.main_thread));
            }
        }) {
            Ok(cleanup) => cleanup,
            Err(error) => {
                GlobalQueueVisitor::remove(&mut main_thread);
                return Err(error);
            }
        };
        main_thread.lock().set_deferred_cleanup(cleanup);
        let id = Thread::id(&main_thread);
        assert!(MEMBERS.irqsave_lock().insert(id, group.clone()).is_none());
        Ok(Self { group })
    }

    #[cfg(all(loader_backend, enable_dynamic_linker, enable_vfs))]
    pub(crate) fn install_linker(&mut self, runtime: Box<LinkerRuntime>) {
        debug_assert_eq!(self.state(), ThreadGroupState::Prepared);
        self.group.with_image_owner(|owner| {
            let owner = owner.as_mut().expect("prepared group retains its owner");
            assert!(matches!(owner.linker, LinkerSlot::Unavailable));
            owner.linker = LinkerSlot::Ready(runtime);
        });
    }

    /// Access the main thread for configuration. Use start() to schedule it;
    /// queuing this node separately bypasses group state transitions.
    /// This handle retains the thread and its stack until ThreadGroup is dropped.
    pub fn thread(&self) -> &ThreadNode {
        &self.group.main_thread
    }
    pub fn state(&self) -> ThreadGroupState {
        self.group.state.irqsave_lock().phase
    }
    /// Includes retired members until their deferred cleanup has completed.
    pub fn member_count(&self) -> usize {
        self.group.state.irqsave_lock().members.len()
    }
    pub fn exit_status(&self) -> Option<ThreadGroupExit> {
        self.group.state.irqsave_lock().outcome
    }

    /// Schedule the main thread once. Child threads share this group's resources.
    pub fn start(&mut self) -> Result<(), ThreadGroupError> {
        if self.state() != ThreadGroupState::Prepared || self.thread().state() != thread::IDLE {
            return Err(ThreadGroupError::AlreadyStarted);
        }
        self.group.state.irqsave_lock().phase = ThreadGroupState::Running;
        if scheduler::queue_ready_thread(thread::IDLE, self.thread().clone()).is_err() {
            self.group.state.irqsave_lock().phase = ThreadGroupState::Prepared;
            self.cancel();
            return Err(ThreadGroupError::QueueFailed);
        }
        Ok(())
    }

    /// Wait until member cleanup, descriptor closing and image release finish.
    /// The main thread and its stack remain retained by this ThreadGroup handle.
    pub fn wait(&self) -> Result<ThreadGroupExit, ThreadGroupError> {
        if self.state() == ThreadGroupState::Prepared {
            return Err(ThreadGroupError::NotStarted);
        }
        loop {
            let epoch = self.group.changed.load(Ordering::Acquire);
            if let Some(status) = self.exit_status() {
                return Ok(status);
            }
            let _result = crate::sync::atomic_wait(&self.group.changed, epoch, Tick::MAX);
        }
    }

    fn cancel(&mut self) {
        let mut main_thread = self.thread().clone();
        if main_thread.state() != thread::IDLE {
            return;
        }
        GlobalQueueVisitor::remove(&mut main_thread);
        let cleanup = main_thread.lock().take_cleanup();
        drop(cleanup);
        self.group.finish(Thread::id(&main_thread));
    }
}
impl Drop for ThreadGroup {
    fn drop(&mut self) {
        if self.state() == ThreadGroupState::Prepared {
            self.cancel();
        }
    }
}

impl ThreadGroupInner {
    // Only transfer ownership under this lock. Local interrupts stay disabled
    // so a higher-priority member on the same CPU cannot spin on it.
    fn with_image_owner<T>(&self, access: impl FnOnce(&mut Option<ImageOwner>) -> T) -> T {
        let _interrupts = DisableInterruptGuard::new();
        let mut owner = self.image_owner.lock();
        access(&mut owner)
    }

    #[cfg(all(loader_backend, enable_dynamic_linker, enable_vfs))]
    pub(crate) fn with_linker<T>(
        &self,
        thread: usize,
        access: LinkerAccess,
        operation: impl FnOnce(&mut LinkerRuntime) -> Result<T, libc::c_int>,
    ) -> Result<T, libc::c_int> {
        let allowed = match access {
            LinkerAccess::Open => self.state.irqsave_lock().phase == ThreadGroupState::Running,
            LinkerAccess::Existing => matches!(
                self.state.irqsave_lock().phase,
                ThreadGroupState::Running | ThreadGroupState::Exiting
            ),
            LinkerAccess::Finalize => {
                let state = self.state.irqsave_lock();
                state.phase == ThreadGroupState::Exiting
                    && state.members.len() == 1
                    && thread == Thread::id(&self.main_thread)
            }
        };
        if !allowed {
            return Err(libc::EBUSY);
        }
        let mut runtime = loop {
            let epoch = self.changed.load(Ordering::Acquire);
            let runtime = self.with_image_owner(|owner| {
                let slot = &mut owner.as_mut().ok_or(libc::ENOSYS)?.linker;
                match slot {
                    LinkerSlot::Ready(_) => {}
                    LinkerSlot::Unavailable => return Err(libc::ENOSYS),
                    LinkerSlot::Busy => return Ok(None),
                }
                let LinkerSlot::Ready(runtime) = core::mem::replace(slot, LinkerSlot::Busy) else {
                    unreachable!("checked the runtime slot while holding its lock");
                };
                Ok(Some(runtime))
            })?;
            if let Some(runtime) = runtime {
                break runtime;
            }
            if matches!(access, LinkerAccess::Open) {
                return Err(libc::EBUSY);
            }
            // A lookup or close may briefly own the runtime while the opener
            // reports completion. Wait for it without holding the owner lock.
            let _result = crate::sync::atomic_wait(&self.changed, epoch, Tick::MAX);
        };
        let result = operation(&mut runtime);
        // The registered caller is still a member, so the reaper cannot
        // take the image owner while this operation is in progress.
        self.with_image_owner(|owner| {
            owner.as_mut().expect("registered group member").linker = LinkerSlot::Ready(runtime);
        });
        self.changed.fetch_add(1, Ordering::Release);
        let _result = crate::sync::atomic_wake(&self.changed, usize::MAX);
        result
    }

    #[cfg(enable_vfs)]
    pub(crate) fn fd_manager(&self) -> &SpinLock<crate::vfs::fd_manager::FdManager> {
        &self.files.table
    }

    pub(crate) fn attach(self: &Arc<Self>, thread: ThreadNode) -> Result<(), ()> {
        let id = Thread::id(&thread);
        {
            let mut state = self.state.irqsave_lock();
            if state.phase != ThreadGroupState::Running {
                return Err(());
            }
            state.members.push(thread);
        }
        // The member retains its ThreadNode, preventing id reuse until cleanup.
        assert!(MEMBERS.irqsave_lock().insert(id, self.clone()).is_none());
        Ok(())
    }

    /// Release a retired member's resources before removing its membership.
    /// The callback runs on a shared worker without the member's identity, TLS
    /// or descriptor table. It may use only resources passed through `argument`;
    /// application finalization must finish before the member retires.
    pub(crate) fn child_cleanup(
        self: &Arc<Self>,
        id: usize,
        callback: Option<extern "C" fn(*mut core::ffi::c_void)>,
        argument: usize,
    ) -> Result<DeferredCleanup, thread::CleanupError> {
        let group: Weak<Self> = Arc::downgrade(self);
        DeferredCleanup::new(move || {
            // The C SpawnArgs contract retains argument storage until cleanup;
            // membership keeps the callback's image mapped through this call.
            if let Some(group) = group.upgrade() {
                if let Some(callback) = callback {
                    callback(argument as *mut core::ffi::c_void);
                }
                group.finish(id);
            }
        })
    }

    pub(crate) fn finish(self: &Arc<Self>, id: usize) {
        let registered = { MEMBERS.irqsave_lock().remove(&id) };
        let (member, complete) = {
            let mut state = self.state.irqsave_lock();
            let Some(index) = state.members.iter().position(|t| Thread::id(t) == id) else {
                return;
            };
            let member = state.members.swap_remove(index);
            let complete = state.members.is_empty();
            if id == Thread::id(&self.main_thread) || complete {
                state.phase = ThreadGroupState::Exiting;
            }
            (member, complete)
        };
        let image_owner = if complete {
            self.with_image_owner(Option::take)
        } else {
            None
        };
        // Resource release may block. No group or registry lock survives here.
        #[cfg(enable_vfs)]
        if complete {
            self.files.close_all();
        }
        drop(image_owner);
        drop(member);
        drop(registered);
        if complete {
            let mut state = self.state.irqsave_lock();
            state.outcome = Some(if state.fini_complete {
                ThreadGroupExit::Code(state.exit_code.expect("normal exit status"))
            } else {
                ThreadGroupExit::Aborted
            });
            state.phase = ThreadGroupState::Exited;
        }
        self.changed.fetch_add(1, Ordering::Release);
        let _result = crate::sync::atomic_wake(&self.changed, usize::MAX);
    }

    pub(crate) fn begin_exit(&self, id: usize, status: i32) -> Result<(), ()> {
        {
            let mut state = self.state.irqsave_lock();
            // First delivery coordinates normal exit from the main thread.
            // It waits for children to finish cooperatively; it does not kill them.
            if id != Thread::id(&self.main_thread) || state.phase != ThreadGroupState::Running {
                return Err(());
            }
            state.exit_code = Some(status);
            state.phase = ThreadGroupState::Exiting;
        }
        loop {
            let epoch = self.changed.load(Ordering::Acquire);
            if self.state.irqsave_lock().members.len() == 1 {
                return Ok(());
            }
            let _result = crate::sync::atomic_wait(&self.changed, epoch, Tick::MAX);
        }
    }

    pub(crate) fn finish_exit(&self, id: usize) -> Result<(), ()> {
        let mut state = self.state.irqsave_lock();
        if id != Thread::id(&self.main_thread)
            || state.phase != ThreadGroupState::Exiting
            || state.members.len() != 1
        {
            return Err(());
        }
        state.fini_complete = true;
        Ok(())
    }
}

pub(crate) fn for_thread(id: usize) -> Option<Arc<ThreadGroupInner>> {
    MEMBERS.irqsave_lock().get(&id).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arch,
        thread::{Builder, Entry},
    };
    use blueos_test_macro::test;
    use core::{ffi::c_void, sync::atomic::AtomicBool};

    #[derive(Default)]
    struct Observed {
        release_main: AtomicBool,
        release_child: AtomicBool,
        child_entered: AtomicBool,
        child_cleaned: AtomicBool,
        dropped: AtomicBool,
        heap_block: AtomicUsize,
    }

    #[must_use]
    struct Owner(Arc<Observed>);
    impl Drop for Owner {
        fn drop(&mut self) {
            assert!(arch::local_irq_enabled());
            assert!(!crate::irq::is_in_irq());
            scheduler::yield_me();
            self.0.dropped.store(true, Ordering::Release);
        }
    }

    fn wait_for(mut ready: impl FnMut() -> bool) {
        let start = crate::time::now();
        while !ready() {
            assert!(crate::time::now().saturating_sub(start) < core::time::Duration::from_secs(2));
            scheduler::yield_me();
        }
    }

    fn alloc_via_syscall(size: usize, align: usize) -> *mut u8 {
        let mut block = core::ptr::null_mut();
        assert_eq!(
            crate::syscalls::alloc_mem::handle(&raw mut block, size, align),
            0
        );
        block.cast()
    }

    fn realloc_via_syscall(old: *mut u8, size: usize, align: usize) -> *mut u8 {
        let mut block = core::ptr::null_mut();
        let status = crate::syscalls::realloc_mem::handle(&raw mut block, old.cast(), size, align);
        if status != 0 {
            assert_eq!(status, -1);
            assert!(block.is_null());
        }
        block.cast()
    }

    fn free_via_syscall(block: *mut u8) {
        assert_eq!(crate::syscalls::free_mem::handle(block.cast()), 0);
    }

    extern "C" fn empty() {}

    #[test]
    fn static_application_uses_thread_group_resources() {
        let group = for_thread(scheduler::current_thread_id())
            .expect("the static test application must have a thread group");
        assert_eq!(group.state.irqsave_lock().phase, ThreadGroupState::Running);
        #[cfg(enable_vfs)]
        {
            let table = group.fd_manager().irqsave_lock();
            for fd in 0..3 {
                assert!(table.is_valid_fd(fd));
            }
        }
    }

    extern "C" fn main_entry(argument: *mut c_void) {
        // The owner and the test retain Observed through all callbacks.
        let observed = unsafe { &*argument.cast::<Observed>() };
        wait_for(|| observed.release_main.load(Ordering::Acquire));
    }
    extern "C" fn child_entry(argument: *mut c_void) {
        let observed = unsafe { &*argument.cast::<Observed>() };
        let block = alloc_via_syscall(128, 16);
        assert!(!block.is_null());
        unsafe { block.write(41) };
        observed
            .heap_block
            .store(block.expose_provenance(), Ordering::Release);
        observed.child_entered.store(true, Ordering::Release);
        wait_for(|| observed.release_child.load(Ordering::Acquire));
        assert!(!observed.dropped.load(Ordering::Acquire));
    }
    extern "C" fn child_cleanup(argument: *mut c_void) {
        let observed = unsafe { &*argument.cast::<Observed>() };
        assert!(arch::local_irq_enabled());
        assert!(!observed.dropped.load(Ordering::Acquire));
        let block = core::ptr::with_exposed_provenance_mut::<u8>(
            observed.heap_block.swap(0, Ordering::AcqRel),
        );
        assert_eq!(unsafe { block.read() }, 41);
        // This callback runs outside the group on the cleanup worker.
        let block = realloc_via_syscall(block, 512, 16);
        assert!(!block.is_null());
        assert_eq!(unsafe { block.read() }, 41);
        free_via_syscall(block);
        observed.child_cleaned.store(true, Ordering::Release);
    }

    extern "C" fn allocating_child(argument: *mut c_void) {
        let observed = unsafe { &*argument.cast::<Observed>() };
        let block = alloc_via_syscall(512, 16);
        assert!(!block.is_null());
        unsafe { block.write(41) };
        observed
            .heap_block
            .store(block.expose_provenance(), Ordering::Release);
    }

    #[test]
    fn thread_group_exit_leaves_application_heap_to_caller() {
        let (mut thread_group, observed) = prepare();
        thread_group.start().unwrap();
        let child = Builder::new(Entry::Posix(
            allocating_child,
            Arc::as_ptr(&observed).cast_mut().cast(),
        ))
        .build();
        let id = Thread::id(&child);
        child
            .lock()
            .set_deferred_cleanup(thread_group.group.child_cleanup(id, None, 0).unwrap());
        thread_group.group.attach(child.clone()).unwrap();
        assert_eq!(scheduler::queue_ready_thread(thread::IDLE, child), Ok(()));
        wait_for(|| {
            observed.heap_block.load(Ordering::Acquire) != 0 && thread_group.member_count() == 1
        });
        assert!(for_thread(id).is_none());
        let block = core::ptr::with_exposed_provenance_mut::<u8>(
            observed.heap_block.load(Ordering::Acquire),
        );
        assert_eq!(unsafe { block.read() }, 41);
        observed.release_main.store(true, Ordering::Release);
        assert_eq!(thread_group.wait(), Ok(ThreadGroupExit::Aborted));
        assert!(observed.dropped.load(Ordering::Acquire));
        // Neither retiring the allocating child nor completing the group owns
        // this block. The caller is responsible for eventually releasing it.
        let block = realloc_via_syscall(block, 1024, 16);
        assert!(!block.is_null());
        assert_eq!(unsafe { block.read() }, 41);
        free_via_syscall(block);
    }

    fn prepare() -> (ThreadGroup, Arc<Observed>) {
        let observed = Arc::new(Observed::default());
        let thread = Builder::new(Entry::Posix(
            main_entry,
            Arc::as_ptr(&observed).cast_mut().cast(),
        ))
        .build();
        let group = ThreadGroup::prepare(
            thread,
            Box::new(Owner(observed.clone())),
            #[cfg(enable_vfs)]
            crate::vfs::fd_manager::FdManager::new(),
        )
        .unwrap();
        (group, observed)
    }

    #[test]
    fn dropping_prepared_thread_group_cancels_registration() {
        let (thread_group, observed) = prepare();
        let id = Thread::id(thread_group.thread());
        assert!(for_thread(id).is_some());
        assert_eq!(thread_group.wait(), Err(ThreadGroupError::NotStarted));
        drop(thread_group);
        assert!(observed.dropped.load(Ordering::Acquire));
        assert!(for_thread(id).is_none());
        assert!(GlobalQueueVisitor::find_if(|t| Thread::id(t) == id).is_none());
    }

    #[test]
    fn thread_group_retains_image_after_abnormal_main_exit() {
        let (mut thread_group, observed) = prepare();
        thread_group.start().unwrap();
        let pointer = Arc::as_ptr(&observed).cast_mut().cast();
        let child = Builder::new(Entry::Posix(child_entry, pointer)).build();
        let id = Thread::id(&child);
        let cleanup = thread_group
            .group
            .child_cleanup(id, Some(child_cleanup), pointer as usize)
            .unwrap();
        thread_group.group.attach(child.clone()).unwrap();
        child.lock().set_deferred_cleanup(cleanup);
        assert_eq!(scheduler::queue_ready_thread(thread::IDLE, child), Ok(()));
        wait_for(|| observed.child_entered.load(Ordering::Acquire));
        observed.release_main.store(true, Ordering::Release);
        wait_for(|| {
            thread_group.state() == ThreadGroupState::Exiting && thread_group.member_count() == 1
        });
        assert_eq!(thread_group.thread().state(), thread::RETIRED);
        assert!(!observed.dropped.load(Ordering::Acquire));
        assert_eq!(thread_group.exit_status(), None);
        // New members cannot extend a group after its main exits.
        let mut rejected = Builder::new(Entry::C(empty)).build();
        assert!(thread_group.group.attach(rejected.clone()).is_err());
        GlobalQueueVisitor::remove(&mut rejected);
        observed.release_child.store(true, Ordering::Release);
        assert_eq!(thread_group.wait(), Ok(ThreadGroupExit::Aborted));
        assert!(observed.child_cleaned.load(Ordering::Acquire));
        assert!(observed.dropped.load(Ordering::Acquire));
        assert!(for_thread(id).is_none());
    }

    #[test]
    fn running_thread_group_survives_dropped_observer() {
        let (mut thread_group, observed) = prepare();
        thread_group.start().unwrap();
        let pointer = Arc::as_ptr(&observed).cast_mut().cast();
        let child = Builder::new(Entry::Posix(child_entry, pointer)).build();
        let id = Thread::id(&child);
        let cleanup = thread_group
            .group
            .child_cleanup(id, Some(child_cleanup), pointer as usize)
            .unwrap();
        thread_group.group.attach(child.clone()).unwrap();
        child.lock().set_deferred_cleanup(cleanup);
        assert_eq!(scheduler::queue_ready_thread(thread::IDLE, child), Ok(()));
        wait_for(|| observed.child_entered.load(Ordering::Acquire));
        let group = Arc::downgrade(&thread_group.group);
        drop(thread_group);
        assert!(group.upgrade().is_some());
        assert!(!observed.dropped.load(Ordering::Acquire));
        observed.release_main.store(true, Ordering::Release);
        wait_for(|| {
            let group = group.upgrade().expect("child must retain the group");
            let state = group.state.irqsave_lock();
            state.phase == ThreadGroupState::Exiting && state.members.len() == 1
        });
        assert!(!observed.dropped.load(Ordering::Acquire));
        assert!(!observed.child_cleaned.load(Ordering::Acquire));
        observed.release_child.store(true, Ordering::Release);
        wait_for(|| group.upgrade().is_none());
        assert!(observed.child_cleaned.load(Ordering::Acquire));
        assert!(observed.dropped.load(Ordering::Acquire));
    }
}
