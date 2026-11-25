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

use super::runner::FileReader;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use blueos::{
    loader::{
        adapters::{KernelCodeCache, MemoryMapper},
        load_request, prepare_linked, run_linked, run_linked_from_path, RunRequest,
    },
    scheduler,
    thread::{Builder, DeferredCleanup, Entry, Stack, IDLE},
    thread_group::{StandardIo, ThreadGroupExit, ThreadGroupState},
    vfs::{self, FileOps},
};
use blueos_loader::{
    dynamic_linker::DependencyResolver,
    error::{ErrorContext, LoadErrorKind},
    load_and_link,
    memory::AllocationOffset,
    profile::{ExportLimits, LinkLimits},
    ImageMapping, LoadAndLinkRequest, LoadError, LoadResult,
};
use blueos_test_macro::test;
use core::{
    ffi::{c_char, CStr},
    sync::atomic::{AtomicUsize, Ordering},
};

unsafe extern "C" {
    static LINKED_TEST_APP_PATH: *const c_char;
    static LINKED_GRAPH_APP_PATH: *const c_char;
    static LINKED_TEST_DSO_PATH: *const c_char;
    static LINKED_TEST_PLUGIN_PATH: *const c_char;
    static LINKED_UNRESOLVED_PLUGIN_PATH: *const c_char;
    static LINKED_CHAIN_LEAF_PATH: *const c_char;
    static LINKED_CHAIN_MIDDLE_PATH: *const c_char;
    static LINKED_CHAIN_PEER_PATH: *const c_char;
    static LINKED_CHAIN_PLUGIN_PATH: *const c_char;
    static LINKED_CYCLE_A_PATH: *const c_char;
    static LINKED_CYCLE_B_PATH: *const c_char;
    static LINKED_SCOPE_PATH: *const c_char;
    static LINKED_SCOPE_CPP_PATH: *const c_char;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Input {
    Application,
    GraphApplication,
    Library,
    Plugin,
    ChainPlugin,
    ChainMiddle,
    ChainPeer,
    ChainLeaf,
    CycleA,
    CycleB,
    UnresolvedPlugin,
    Scope,
    ScopeCpp,
}

impl Input {
    fn host_path(self) -> *const c_char {
        // SAFETY: these linker-provided pointers name live host fixture paths.
        unsafe {
            match self {
                Self::Application => LINKED_TEST_APP_PATH,
                Self::GraphApplication => LINKED_GRAPH_APP_PATH,
                Self::Library => LINKED_TEST_DSO_PATH,
                Self::Plugin => LINKED_TEST_PLUGIN_PATH,
                Self::ChainPlugin => LINKED_CHAIN_PLUGIN_PATH,
                Self::ChainMiddle => LINKED_CHAIN_MIDDLE_PATH,
                Self::ChainPeer => LINKED_CHAIN_PEER_PATH,
                Self::ChainLeaf => LINKED_CHAIN_LEAF_PATH,
                Self::CycleA => LINKED_CYCLE_A_PATH,
                Self::CycleB => LINKED_CYCLE_B_PATH,
                Self::UnresolvedPlugin => LINKED_UNRESOLVED_PLUGIN_PATH,
                Self::Scope => LINKED_SCOPE_PATH,
                Self::ScopeCpp => LINKED_SCOPE_CPP_PATH,
            }
        }
    }
}

// Allow for application frames above the loader's stack check.
const RUNTIME_STACK_SIZE: usize = (if cfg!(debug_assertions) { 9 } else { 8 }) * 1024;
const PLUGIN_PATH: &CStr = c"/linked-fixtures/linked-plugin.so";
const PLUGIN_FILES: &[(Input, &CStr)] = &[(Input::Plugin, PLUGIN_PATH)];
const DIAMOND_FILES: &[(Input, &CStr)] = &[
    (
        Input::ChainPlugin,
        c"/linked-fixtures/liblinked_chain_plugin.so",
    ),
    (
        Input::ChainMiddle,
        c"/linked-fixtures/liblinked_chain_middle.so",
    ),
    (
        Input::ChainPeer,
        c"/linked-fixtures/liblinked_chain_peer.so",
    ),
    (
        Input::ChainLeaf,
        c"/linked-fixtures/liblinked_chain_leaf.so",
    ),
];
const CYCLE_FILES: &[(Input, &CStr)] = &[
    (Input::CycleA, c"/linked-fixtures/liblinked_cycle_a.so"),
    (Input::CycleB, c"/linked-fixtures/liblinked_cycle_b.so"),
];

struct Fixtures {
    open_library: bool,
}

impl DependencyResolver for Fixtures {
    type Key = Input;
    type Reader = FileReader;

    fn resolve(&mut self, requester: &Input, name: &[u8]) -> LoadResult<Input> {
        if matches!(requester, Input::Application | Input::Plugin)
            && name == b"liblinked_test_dso.so"
        {
            return Ok(Input::Library);
        }
        Err(LoadError::new(LoadErrorKind::Io, ErrorContext::None))
    }

    fn open(&mut self, key: &Input) -> LoadResult<Self::Reader> {
        if *key == Input::Library && !self.open_library {
            return Err(LoadError::new(LoadErrorKind::Io, ErrorContext::None));
        }
        // SAFETY: the fixture path is a live NUL-terminated string.
        let path = unsafe { CStr::from_ptr(key.host_path()) };
        FileReader::open(path).map_err(|_| LoadError::new(LoadErrorKind::Io, ErrorContext::None))
    }
}

#[test]
fn test_linked_thread_group_runs_dso_callbacks_and_main() {
    check_startup(c"LINK_TEST=normal", 42, b"PDIMFd");
}

#[test]
fn test_linked_thread_group_retires_after_exit_from_a_constructor() {
    check_startup(c"LINK_TEST=abort", 19, b"PD");
}

#[test]
fn test_linked_thread_group_starts_with_diamond_and_cyclic_dependencies() {
    let libraries: Vec<_> = DIAMOND_FILES.iter().chain(CYCLE_FILES).copied().collect();
    with_vfs_fixtures(Input::GraphApplication, &libraries, |app| {
        check_path(
            app,
            "/linked-output",
            RunRequest {
                envp: &[c"LINK_TEST=startup-graph"],
                ..RunRequest::default()
            },
            42,
            b"PDBACXABIMFbaxcabd",
        );
    });
}

#[test]
fn test_runtime_plugin_runs_callbacks_and_reuses_the_published_image() {
    check_runtime(
        c"LINK_TEST=runtime",
        PLUGIN_FILES,
        RUNTIME_STACK_SIZE,
        44,
        b"PDIMLlFd",
    );
}

#[test]
fn test_runtime_plugin_shares_and_finalizes_diamond_dependencies() {
    // B is reached through both A and C. It initializes once before either.
    check_runtime(
        c"LINK_TEST=runtime-chain",
        DIAMOND_FILES,
        RUNTIME_STACK_SIZE,
        0,
        b"PDIMBACXRxcabFd",
    );
}

#[test]
fn test_runtime_plugin_links_cyclic_dependencies() {
    // A and B initialize in discovery order within the cycle and finalize in reverse.
    check_runtime(
        c"LINK_TEST=runtime-cycle",
        CYCLE_FILES,
        RUNTIME_STACK_SIZE,
        0,
        b"PDIMABRbaFd",
    );
}

#[test]
fn test_runtime_plugin_can_retry_after_unresolved_symbol() {
    // E follows the failed open. Only the replacement plugin runs callbacks.
    check_runtime(
        c"LINK_TEST=runtime-retry",
        &[
            (Input::UnresolvedPlugin, PLUGIN_PATH),
            (Input::Plugin, c"/linked-fixtures/linked-plugin-retry.so"),
        ],
        RUNTIME_STACK_SIZE,
        44,
        b"PDIMELRlFd",
    );
}

#[test]
fn test_runtime_c_and_cpp_plugins_bind_symbols_and_keep_emutls_per_thread() {
    check_runtime(
        c"LINK_TEST=runtime-scope",
        &[
            (Input::Scope, c"/linked-fixtures/liblinked_scope.so"),
            (Input::Scope, c"/linked-fixtures/alternate-scope.so"),
            (Input::ScopeCpp, c"/linked-fixtures/liblinked_scope_cpp.so"),
        ],
        RUNTIME_STACK_SIZE,
        42,
        b"PDIMQSSRssqFd",
    );
}

#[test]
fn test_runtime_plugin_handles_and_writable_mappings_belong_to_the_thread_group() {
    with_vfs_fixtures(Input::Application, PLUGIN_FILES, |app| {
        let done = Arc::new(AtomicUsize::new(0));
        let completed = done.clone();
        let first = Builder::new(Entry::Closure(Box::new(move || {
            check_path(
                app,
                "/linked-owner-output",
                runtime_request(&[c"LINK_TEST=runtime-holding"], RUNTIME_STACK_SIZE),
                44,
                b"PDIMLRlFd",
            );
        })))
        .set_stack(Stack::from_size(16 * 1024).unwrap())
        .build();
        first.lock().set_deferred_cleanup(
            DeferredCleanup::new(move || {
                completed.store(1, Ordering::Release);
                blueos::sync::wake(&completed);
            })
            .unwrap(),
        );
        assert_eq!(scheduler::queue_ready_thread(IDLE, first.clone()), Ok(()));

        check_path(
            app,
            "/linked-peer-output",
            runtime_request(&[c"LINK_TEST=runtime-peer"], RUNTIME_STACK_SIZE),
            44,
            b"PDIMLRlFd",
        );
        blueos::sync::wait_until(1, &done);
        for path in [c"/linked-fixtures/handle", c"/linked-fixtures/release"] {
            assert_eq!(vfs::syscalls::unlink(path.as_ptr()), 0);
        }
    });
}

#[test]
fn test_runtime_plugin_constructor_can_exit_before_publication() {
    check_runtime(
        c"LINK_TEST=runtime-abort",
        PLUGIN_FILES,
        RUNTIME_STACK_SIZE,
        19,
        b"PDIMLFd",
    );
}

#[test]
fn test_runtime_plugin_rejects_insufficient_linker_stack() {
    check_runtime(
        c"LINK_TEST=runtime-small-stack",
        PLUGIN_FILES,
        4 * 1024,
        21,
        b"PDIMFd",
    );
}

#[test]
fn test_plugin_reuses_startup_library_with_application_symbol_precedence() {
    let request = LoadAndLinkRequest::new(load_request())
        .with_link_limits(LinkLimits::DEFAULT.with_export_limits(ExportLimits::DEFAULT));
    let mut fixtures = Fixtures { open_library: true };
    let mut allocator = MemoryMapper::new();
    let mut cache = KernelCodeCache::new();
    let mut images = load_and_link(
        Input::Application,
        request,
        &mut fixtures,
        &mut allocator,
        &mut cache,
    )
    .unwrap();
    fixtures.open_library = false;
    let index = images
        .load_plugin(
            Input::Plugin,
            request,
            &mut fixtures,
            &mut allocator,
            &mut cache,
        )
        .unwrap();
    assert_eq!(index, 2);
    assert_eq!(images.images().len(), 3);
    assert_eq!(images.edges().len(), 2);
    assert_eq!(images.edges()[1].requester(), index);
    assert_eq!(images.edges()[1].provider(), 1);
    assert_eq!(images.init_order(), [1, 0, 2]);

    let plugin = &images.images()[index];
    let allocation = plugin.image().allocation();
    for (slot, provider, name) in [
        (b"plugin_choice".as_slice(), 0, b"linked_choice".as_slice()),
        (b"plugin_value", 1, b"linked_value"),
        (b"plugin_data", 1, b"linked_data"),
    ] {
        let slot = plugin.exports().unwrap().find(slot).unwrap();
        let expected = images.images()[provider]
            .exports()
            .unwrap()
            .find(name)
            .unwrap();
        let mut bytes = [0; size_of::<usize>()];
        allocation
            .read(
                AllocationOffset::new(slot.checked_sub(allocation.base()).unwrap()),
                &mut bytes,
            )
            .unwrap();
        assert_eq!(usize::from_ne_bytes(bytes) as u64, expected.get());
    }
    let host = images.images()[0]
        .exports()
        .unwrap()
        .find(b"linked_choice")
        .unwrap();
    let library = images.images()[1]
        .exports()
        .unwrap()
        .find(b"linked_choice")
        .unwrap();
    assert_ne!(host, library);
    assert_eq!(
        images.lookup_symbol(0, b"linked_choice").unwrap(),
        Some(host)
    );
    assert_eq!(
        images.lookup_symbol(index, b"linked_choice").unwrap(),
        Some(library)
    );
    assert_eq!(images.lookup_symbol(index, b"record_event").unwrap(), None);
}

#[test]
fn test_preloaded_plugin_shares_only_its_own_thread_groups_library() {
    let request = LoadAndLinkRequest::new(load_request())
        .with_link_limits(LinkLimits::DEFAULT.with_export_limits(ExportLimits::DEFAULT));
    let mut resolver = Fixtures { open_library: true };
    let mut allocator = MemoryMapper::new();
    let mut cache = KernelCodeCache::new();
    let mut first = load_and_link(
        Input::Application,
        request,
        &mut resolver,
        &mut allocator,
        &mut cache,
    )
    .unwrap();
    let second = load_and_link(
        Input::Application,
        request,
        &mut resolver,
        &mut allocator,
        &mut cache,
    )
    .unwrap();
    let library_data = |images: &blueos_loader::LoadedImages<Input, _>| {
        images.images()[1]
            .exports()
            .unwrap()
            .find(b"linked_data")
            .unwrap()
    };
    assert_ne!(library_data(&first), library_data(&second));

    // Reuse the mapped dependency even when its source can no longer be opened.
    resolver.open_library = false;
    let rejected =
        request.with_link_limits(LinkLimits::DEFAULT.with_export_limits(ExportLimits::new(0, 0)));
    let error = first
        .load_plugin(
            Input::Plugin,
            rejected,
            &mut resolver,
            &mut allocator,
            &mut cache,
        )
        .unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
    assert_eq!(first.images().len(), 2);
    assert_eq!(first.edges().len(), 1);
    assert_eq!(first.init_order(), [1, 0]);

    for _ in 0..2 {
        assert_eq!(
            first
                .load_plugin(
                    Input::Plugin,
                    request,
                    &mut resolver,
                    &mut allocator,
                    &mut cache
                )
                .unwrap(),
            2,
        );
    }
    assert_eq!(first.images().len(), 3);
    assert_eq!(first.init_order(), [1, 0, 2]);

    let (first_output, first_stdio) = capture_output("/linked-plugin-output");
    let (second_output, second_stdio) = capture_output("/linked-peer-output");
    let first_request = RunRequest {
        envp: &[c"LINK_TEST=plugin"],
        stdio: Some(&first_stdio),
        ..RunRequest::default()
    };
    let second_request = RunRequest {
        envp: &[c"LINK_TEST=normal"],
        stdio: Some(&second_stdio),
        ..RunRequest::default()
    };
    // SAFETY: both fixtures use the production CRT in independent native mappings.
    let (mut first, mut second) = unsafe {
        (
            prepare_linked(first, &first_request).unwrap(),
            prepare_linked(second, &second_request).unwrap(),
        )
    };
    assert_eq!(first.state(), ThreadGroupState::Prepared);
    first.start().unwrap();
    assert_eq!(first.wait().unwrap(), ThreadGroupExit::Code(44));
    check_events(&first_output, b"PDILMlFd");
    drop(first);

    assert_eq!(second.state(), ThreadGroupState::Prepared);
    second.start().unwrap();
    assert_eq!(second.wait().unwrap(), ThreadGroupExit::Code(42));
    check_events(&second_output, b"PDIMFd");
}

fn capture_output(path: &str) -> (Arc<vfs::File>, StandardIo) {
    let output = Arc::new(
        vfs::open_path(path, libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR, 0o600).unwrap(),
    );
    let stdio = StandardIo {
        stdin: output.clone(),
        stdout: output.clone(),
        stderr: output.clone(),
    };
    (output, stdio)
}

fn check_events(output: &vfs::File, expected_events: &[u8]) {
    let mut events = [0; 32];
    let count = output.read_at(0, &mut events).unwrap();
    assert_eq!(&events[..count], expected_events);
}

fn check_startup(env: &CStr, status: i32, expected_events: &[u8]) {
    let request = RunRequest {
        envp: &[env],
        ..RunRequest::default()
    };
    check_launch(
        "/linked-output",
        request,
        status,
        expected_events,
        |request| {
            let mut resolver = Fixtures { open_library: true };
            // SAFETY: the fixtures are native inputs using the production librs CRT.
            unsafe { run_linked(Input::Application, &mut resolver, request) }.unwrap()
        },
    );
}

fn check_runtime(
    env: &CStr,
    plugins: &[(Input, &CStr)],
    stack_size: usize,
    status: i32,
    expected_events: &[u8],
) {
    with_vfs_fixtures(Input::Application, plugins, |app| {
        check_path(
            app,
            "/linked-output",
            runtime_request(&[env], stack_size),
            status,
            expected_events,
        );
    });
}

fn runtime_request<'a>(envp: &'a [&'a CStr], stack_size: usize) -> RunRequest<'a> {
    RunRequest {
        argv: &[c"linked-runtime.elf", c"test-plugin-args"],
        envp,
        stack_size,
        ..RunRequest::default()
    }
}

fn check_path(app: &CStr, output: &str, request: RunRequest<'_>, status: i32, events: &[u8]) {
    check_launch(output, request, status, events, |request| {
        // SAFETY: these native fixtures use the production CRT. Replacement
        // DSO bytes are written between synchronous opens.
        unsafe { run_linked_from_path(app.to_str().unwrap(), request) }.unwrap()
    });
}

fn check_launch(
    output: &str,
    request: RunRequest<'_>,
    status: i32,
    expected_events: &[u8],
    run: impl FnOnce(&RunRequest<'_>) -> ThreadGroupExit,
) {
    let (output, stdio) = capture_output(output);
    let request = RunRequest {
        stdio: Some(&stdio),
        ..request
    };
    assert_eq!(run(&request), ThreadGroupExit::Code(status));
    check_events(&output, expected_events);
}

fn with_vfs_fixtures(root: Input, libraries: &[(Input, &CStr)], run: impl FnOnce(&'static CStr)) {
    let directory = c"/linked-fixtures";
    assert_eq!(vfs::syscalls::mkdir(directory.as_ptr(), 0o700), 0);
    let app = c"/linked-fixtures/linked-runtime.elf";
    let startup = [
        (root, app),
        (Input::Library, c"/linked-fixtures/liblinked_test_dso.so"),
    ];
    let fixtures = startup.into_iter().chain(libraries.iter().copied());
    for (input, path) in fixtures.clone() {
        let bytes = super::read_all(input.host_path()).unwrap();
        let file = vfs::open_path(
            path.to_str().unwrap(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
            0o600,
        )
        .unwrap();
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            let written = file.write(rest).unwrap();
            assert_ne!(written, 0);
            rest = &rest[written..];
        }
    }
    run(app);
    for (_, path) in fixtures {
        assert_eq!(vfs::syscalls::unlink(path.as_ptr()), 0);
    }
    assert_eq!(vfs::syscalls::rmdir(directory.as_ptr()), 0);
}
