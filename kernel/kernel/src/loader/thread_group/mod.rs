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
//! Registered members retain their group; retirement callbacks hold weak handles.
//! ThreadGroupInner therefore survives a dropped ThreadGroup without an Arc cycle.

use crate::{
    scheduler,
    sync::SpinLock,
    thread::{self, DeferredCleanup, GlobalQueueVisitor, Thread, ThreadNode},
    time::Tick,
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

mod heap;
pub(crate) use heap::{allocate_heap, free_heap, reallocate_heap};
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
    #[cfg(enable_vfs)]
    FileTable(crate::error::Error),
    QueueFailed,
}

/// Observe and start a thread group. Dropping a prepared handle cancels startup;
/// dropping a running handle leaves its members owning the image through exit.
#[must_use = "start the thread group or drop it to cancel its prepared resources"]
pub struct ThreadGroup {
    group: Arc<ThreadGroupInner>,
    // Configuration handle; retained until this ThreadGroup is dropped, even
    // after wait() returns. Cloning a ThreadNode shares the same thread and stack.
    main_thread: ThreadNode,
}

/// Shared group lifetime, retained by registered members independently of
/// the public ThreadGroup handle. Retirement callbacks only hold weak references.
#[must_use = "retain group resources until all member cleanups finish"]
pub(crate) struct ThreadGroupInner {
    state: SpinLock<GroupState>,
    #[cfg(enable_vfs)]
    files: files::ThreadGroupFiles,
    // Exclusive ownership transfer needs Send, not shared access to the image.
    // Only the last member takes this value, outside the state lock.
    image_owner: Mutex<Option<Box<dyn Send>>>,
    changed: AtomicUsize,
}

/// Membership, exit progress and heap ownership coordinated by one state lock.
#[must_use = "retain member threads and heap blocks until group cleanup"]
struct GroupState {
    phase: ThreadGroupState,
    exit_code: Option<i32>,
    fini_complete: bool,
    outcome: Option<ThreadGroupExit>,
    // Includes retired threads until their deferred cleanup completes.
    members: Vec<ThreadNode>,
    main_id: usize,
    // Keep the main stack (argv/envp/auxv backing) through the last member's
    // cleanup, even after main leaves members and ThreadGroup has been dropped.
    retained_main: Option<ThreadNode>,
    // malloc-family blocks belong to the whole group, not one thread.
    allocations: Vec<heap::HeapBlock>,
}

// Each registered thread retains its group until its deferred cleanup finishes.
static MEMBERS: SpinLock<BTreeMap<usize, Arc<ThreadGroupInner>>> = SpinLock::new(BTreeMap::new());

/// Borrow group resources while a retired member's C cleanup runs on a
/// kernel worker. This does not make the worker a member or affect exit counts.
#[must_use = "retain the resource context until the cleanup callback returns"]
struct CleanupContext {
    thread_id: usize,
    previous: Option<Arc<ThreadGroupInner>>,
}

impl CleanupContext {
    fn enter(group: &Arc<ThreadGroupInner>) -> Self {
        let thread_id = scheduler::current_thread_id();
        let previous = MEMBERS.irqsave_lock().insert(thread_id, group.clone());
        Self {
            thread_id,
            previous,
        }
    }
}

impl Drop for CleanupContext {
    fn drop(&mut self) {
        let current = {
            let mut members = MEMBERS.irqsave_lock();
            if let Some(previous) = self.previous.take() {
                members.insert(self.thread_id, previous)
            } else {
                members.remove(&self.thread_id)
            }
        };
        drop(current);
    }
}

impl ThreadGroup {
    /// Access the main thread for configuration. Use start() to schedule it;
    /// queuing this node separately bypasses group state transitions.
    /// This handle retains the thread and its stack until ThreadGroup is dropped.
    pub fn thread(&self) -> &ThreadNode {
        &self.main_thread
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

    /// Replace standard descriptors before scheduling. Other descriptors and
    /// streams belong to this group, independently of Process.
    #[cfg(enable_vfs)]
    pub fn set_standard_io(&mut self, stdio: &StandardIo) -> Result<(), ThreadGroupError> {
        if self.state() != ThreadGroupState::Prepared {
            return Err(ThreadGroupError::AlreadyStarted);
        }
        self.group.files.set_stdio(stdio);
        Ok(())
    }

    /// Schedule the main thread once. Child threads share this group's resources.
    pub fn start(&mut self) -> Result<(), ThreadGroupError> {
        if self.state() != ThreadGroupState::Prepared || self.main_thread.state() != thread::IDLE {
            return Err(ThreadGroupError::AlreadyStarted);
        }
        #[cfg(enable_vfs)]
        if let Err(error) = self.group.files.prepare_stdio() {
            self.cancel();
            return Err(ThreadGroupError::FileTable(error));
        }
        self.group.state.irqsave_lock().phase = ThreadGroupState::Running;
        if scheduler::queue_ready_thread(thread::IDLE, self.main_thread.clone()).is_err() {
            self.group.state.irqsave_lock().phase = ThreadGroupState::Prepared;
            self.cancel();
            return Err(ThreadGroupError::QueueFailed);
        }
        Ok(())
    }

    /// Wait until member cleanup, descriptor closing, heap reclamation and image
    /// release finish.
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
        if self.main_thread.state() != thread::IDLE {
            return;
        }
        GlobalQueueVisitor::remove(&mut self.main_thread);
        let cleanup = self.main_thread.lock().take_cleanup();
        drop(cleanup);
        self.group.finish(Thread::id(&self.main_thread));
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
    pub(super) fn prepare(image_owner: Box<dyn Send>) -> Arc<Self> {
        #[cfg(enable_vfs)]
        let files = files::ThreadGroupFiles::new();
        Arc::new(Self {
            state: SpinLock::new(GroupState {
                phase: ThreadGroupState::Prepared,
                exit_code: None,
                fini_complete: false,
                outcome: None,
                members: Vec::new(),
                main_id: 0,
                retained_main: None,
                allocations: Vec::new(),
            }),
            #[cfg(enable_vfs)]
            files,
            image_owner: Mutex::new(Some(image_owner)),
            changed: AtomicUsize::new(0),
        })
    }

    #[cfg(enable_vfs)]
    pub(crate) fn fd_manager(&self) -> &SpinLock<crate::vfs::fd_manager::FdManager> {
        &self.files.table
    }

    pub(super) fn main_cleanup(self: &Arc<Self>) -> Result<DeferredCleanup, thread::CleanupError> {
        let group = Arc::downgrade(self);
        DeferredCleanup::new(move || {
            if let Some(group) = group.upgrade() {
                let id = group.state.irqsave_lock().main_id;
                group.finish(id);
            }
        })
    }

    pub(super) fn install(self: &Arc<Self>, main_thread: ThreadNode) -> ThreadGroup {
        let id = Thread::id(&main_thread);
        {
            let mut state = self.state.irqsave_lock();
            state.main_id = id;
            state.retained_main = Some(main_thread.clone());
            state.members.push(main_thread.clone());
        }
        assert!(MEMBERS.irqsave_lock().insert(id, self.clone()).is_none());
        ThreadGroup {
            group: self.clone(),
            main_thread,
        }
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
                {
                    let _context = CleanupContext::enter(&group);
                    if let Some(callback) = callback {
                        callback(argument as *mut core::ffi::c_void);
                    }
                }
                group.finish(id);
            }
        })
    }

    pub(crate) fn finish(self: &Arc<Self>, id: usize) {
        let registered = { MEMBERS.irqsave_lock().remove(&id) };
        let (member, retained_main, allocations, complete) = {
            let mut state = self.state.irqsave_lock();
            let Some(index) = state.members.iter().position(|t| Thread::id(t) == id) else {
                return;
            };
            let member = state.members.swap_remove(index);
            if id == state.main_id {
                state.phase = ThreadGroupState::Exiting;
            }
            if state.members.is_empty() {
                state.phase = ThreadGroupState::Exiting;
                (
                    member,
                    state.retained_main.take(),
                    core::mem::take(&mut state.allocations),
                    true,
                )
            } else {
                (member, None, Vec::new(), false)
            }
        };
        let image_owner = if complete {
            self.image_owner.lock().take()
        } else {
            None
        };
        // Resource release may block. No group or registry lock survives here.
        #[cfg(enable_vfs)]
        if complete {
            self.files.close_all();
        }
        drop(allocations);
        drop(image_owner);
        drop(retained_main);
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
            if id != state.main_id || state.phase != ThreadGroupState::Running {
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
        if id != state.main_id
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
        normal_exit: AtomicBool,
        heap_block: AtomicUsize,
        untracked_block: AtomicUsize,
        heap_released: Arc<AtomicUsize>,
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

    fn observe_release(block: *mut u8, observed: &Observed) {
        let group = for_thread(scheduler::current_thread_id()).unwrap();
        group
            .state
            .irqsave_lock()
            .allocations
            .iter_mut()
            .find(|owned| owned.address() == block.addr())
            .expect("allocation syscall must register its block")
            .observe_release(observed.heap_released.clone());
    }
    extern "C" fn empty() {}
    extern "C" fn main_entry(argument: *mut c_void) {
        // The owner and the test retain Observed through all callbacks.
        let observed = unsafe { &*argument.cast::<Observed>() };
        wait_for(|| observed.release_main.load(Ordering::Acquire));
    }
    extern "C" fn child_entry(argument: *mut c_void) {
        let observed = unsafe { &*argument.cast::<Observed>() };
        let block = alloc_via_syscall(128, 16);
        assert!(!block.is_null());
        observe_release(block, observed);
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

    extern "C" fn heap_entry(argument: *mut c_void) {
        let observed = unsafe { &*argument.cast::<Observed>() };
        let group = for_thread(scheduler::current_thread_id()).unwrap();
        let block = alloc_via_syscall(64, 64);
        assert!(!block.is_null());
        observe_release(block, observed);
        unsafe { block.write_bytes(0x5a, 64) };
        let failed = realloc_via_syscall(block, isize::MAX as usize - 63, 64);
        assert!(failed.is_null());
        assert!(group
            .state
            .irqsave_lock()
            .allocations
            .iter()
            .any(|owned| owned.address() == block.addr()));
        assert_eq!(unsafe { block.read() }, 0x5a);
        let moved = realloc_via_syscall(block, 4096, 64);
        assert!(!moved.is_null());
        assert_ne!(moved, block);
        assert_eq!(moved.addr() % 64, 0);
        assert_eq!(unsafe { moved.add(63).read() }, 0x5a);
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 0);
        free_via_syscall(moved);
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 1);
        let zeroed = realloc_via_syscall(core::ptr::null_mut(), 128, 16);
        assert!(!zeroed.is_null());
        observe_release(zeroed, observed);
        assert!(realloc_via_syscall(zeroed, 0, 16).is_null());
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 2);
        assert!(group.state.irqsave_lock().allocations.is_empty());

        // An incoming kernel-owned block remains independent even if resized
        // by a member. It must survive group completion.
        let external = core::ptr::with_exposed_provenance_mut::<u8>(
            observed.untracked_block.load(Ordering::Acquire),
        );
        let external = realloc_via_syscall(external, 8192, 16);
        assert!(!external.is_null());
        assert_eq!(unsafe { external.read() }, 23);
        observed
            .untracked_block
            .store(external.expose_provenance(), Ordering::Release);
        assert!(group.state.irqsave_lock().allocations.is_empty());

        // Deliberately leave one block as a static std object would do.
        let remaining = alloc_via_syscall(512, 16);
        assert!(!remaining.is_null());
        observe_release(remaining, observed);
        observed
            .heap_block
            .store(remaining.expose_provenance(), Ordering::Release);
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 2);
        // Do not retain a strong group reference on a retiring thread's stack.
        drop(group);
        if observed.normal_exit.load(Ordering::Acquire) {
            assert_eq!(crate::syscalls::thread_group_begin_exit::handle(0), 0);
            let status = crate::syscalls::thread_group_finish_exit::handle();
            panic!("normal thread group exit returned: {status}");
        }
    }

    #[test]
    fn thread_group_reclaims_heap_without_adopting_incoming_blocks() {
        for normal_exit in [false, true] {
            for _ in 0..5 {
                check_heap_reclamation(normal_exit);
            }
        }
    }

    fn check_heap_reclamation(normal_exit: bool) {
        let observed = Arc::new(Observed::default());
        observed.normal_exit.store(normal_exit, Ordering::Release);
        let external = crate::allocator::malloc_align(64, 16);
        assert!(!external.is_null());
        unsafe { external.write(23) };
        observed
            .untracked_block
            .store(external.expose_provenance(), Ordering::Release);
        let group = ThreadGroupInner::prepare(Box::new(Owner(observed.clone())));
        let thread = Builder::new(Entry::Posix(
            heap_entry,
            Arc::as_ptr(&observed).cast_mut().cast(),
        ))
        .build();
        thread
            .lock()
            .set_deferred_cleanup(group.main_cleanup().unwrap());
        let mut thread_group = group.install(thread);
        thread_group.start().unwrap();
        assert_eq!(
            thread_group.wait(),
            Ok(if normal_exit {
                ThreadGroupExit::Code(0)
            } else {
                ThreadGroupExit::Aborted
            })
        );
        // Explicit free and realloc(0) release two owners. Group exit must
        // release the deliberately retained third owner before wait returns.
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 3);
        assert_ne!(observed.heap_block.load(Ordering::Acquire), 0);
        assert!(group.state.irqsave_lock().allocations.is_empty());
        let external = core::ptr::with_exposed_provenance_mut::<u8>(
            observed.untracked_block.load(Ordering::Acquire),
        );
        assert_eq!(unsafe { external.read() }, 23);
        crate::allocator::free(external);
    }

    extern "C" fn allocating_child(argument: *mut c_void) {
        let observed = unsafe { &*argument.cast::<Observed>() };
        let block = alloc_via_syscall(512, 16);
        assert!(!block.is_null());
        observe_release(block, observed);
        unsafe { block.write(41) };
        observed
            .heap_block
            .store(block.expose_provenance(), Ordering::Release);
    }

    #[test]
    fn child_heap_allocation_survives_its_allocating_thread() {
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
        assert!(thread_group
            .group
            .state
            .irqsave_lock()
            .allocations
            .iter()
            .any(|owned| owned.address() == block.addr()));
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 0);
        observed.release_main.store(true, Ordering::Release);
        assert_eq!(thread_group.wait(), Ok(ThreadGroupExit::Aborted));
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 1);
        assert!(thread_group
            .group
            .state
            .irqsave_lock()
            .allocations
            .is_empty());
    }

    fn prepare() -> (ThreadGroup, Arc<Observed>) {
        let observed = Arc::new(Observed::default());
        let group = ThreadGroupInner::prepare(Box::new(Owner(observed.clone())));
        let cleanup = group.main_cleanup().unwrap();
        let thread = Builder::new(Entry::Posix(
            main_entry,
            Arc::as_ptr(&observed).cast_mut().cast(),
        ))
        .build();
        thread.lock().set_deferred_cleanup(cleanup);
        (group.install(thread), observed)
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
        assert!(thread_group
            .group
            .state
            .irqsave_lock()
            .allocations
            .iter()
            .any(|owned| owned.address() == observed.heap_block.load(Ordering::Acquire)));
        // New members cannot extend a group after its main exits.
        let mut rejected = Builder::new(Entry::C(empty)).build();
        assert!(thread_group.group.attach(rejected.clone()).is_err());
        GlobalQueueVisitor::remove(&mut rejected);
        observed.release_child.store(true, Ordering::Release);
        assert_eq!(thread_group.wait(), Ok(ThreadGroupExit::Aborted));
        assert!(observed.child_cleaned.load(Ordering::Acquire));
        assert_eq!(observed.heap_released.load(Ordering::Acquire), 1);
        assert!(observed.dropped.load(Ordering::Acquire));
        assert!(for_thread(id).is_none());
        assert!(thread_group
            .group
            .state
            .irqsave_lock()
            .allocations
            .is_empty());
    }

    #[test]
    fn running_thread_group_survives_dropped_observer() {
        let (mut thread_group, observed) = prepare();
        thread_group.start().unwrap();
        let group = Arc::downgrade(&thread_group.group);
        drop(thread_group);
        assert!(group.upgrade().is_some());
        assert!(!observed.dropped.load(Ordering::Acquire));
        observed.release_main.store(true, Ordering::Release);
        wait_for(|| group.upgrade().is_none());
        assert!(observed.dropped.load(Ordering::Acquire));
    }
}
