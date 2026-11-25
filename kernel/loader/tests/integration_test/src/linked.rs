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
use alloc::sync::Arc;
use blueos::{
    loader::{
        adapters::{KernelCodeCache, MemoryMapper},
        load_request, prepare_linked, run_linked, run_linked_from_path, RunRequest,
    },
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
use core::ffi::{c_char, CStr};

unsafe extern "C" {
    static LINKED_TEST_APP_PATH: *const c_char;
    static LINKED_TEST_DSO_PATH: *const c_char;
    static LINKED_TEST_PLUGIN_PATH: *const c_char;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Input {
    Application,
    Library,
    Plugin,
}

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
        // SAFETY: these linker-provided pointers name live host fixture paths.
        let path = unsafe {
            CStr::from_ptr(match key {
                Input::Application => LINKED_TEST_APP_PATH,
                Input::Library => LINKED_TEST_DSO_PATH,
                Input::Plugin => LINKED_TEST_PLUGIN_PATH,
            })
        };
        FileReader::open(path).map_err(|_| LoadError::new(LoadErrorKind::Io, ErrorContext::None))
    }
}

#[test]
fn test_linked_thread_group_runs_dso_callbacks_and_main() {
    check_launch(c"LINK_TEST=normal", false, 42, b"PDIMFd");
}

#[test]
fn test_linked_thread_group_retires_after_exit_from_a_constructor() {
    check_launch(c"LINK_TEST=abort", false, 19, b"PD");
}

#[test]
fn test_runtime_plugin_runs_callbacks_and_reuses_the_published_image() {
    check_launch(c"LINK_TEST=runtime", true, 44, b"PDIMLlFd");
}

#[test]
fn test_runtime_plugin_constructor_can_exit_before_publication() {
    check_launch(c"LINK_TEST=runtime-abort", true, 19, b"PDIMLFd");
}

#[test]
fn test_runtime_plugin_rejects_insufficient_linker_stack() {
    check_launch(c"LINK_TEST=runtime-small-stack", true, 21, b"PDIMFd");
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
    let mut events = [0; 16];
    let count = output.read_at(0, &mut events).unwrap();
    assert_eq!(&events[..count], expected_events);
}

fn check_launch(env: &CStr, runtime_plugins: bool, status: i32, expected_events: &[u8]) {
    let (output, stdio) = capture_output("/linked-output");
    let mut request = RunRequest::default();
    if runtime_plugins {
        request.stack_size = if env == c"LINK_TEST=runtime-small-stack" {
            4 * 1024
        } else {
            // Include the application's frames above the loader's stack check.
            (if cfg!(debug_assertions) { 9 } else { 8 }) * 1024
        };
    }
    let request = RunRequest {
        argv: if runtime_plugins {
            &[c"linked-runtime.elf", c"test-plugin-args"]
        } else {
            &[]
        },
        envp: &[env],
        stdio: Some(&stdio),
        ..request
    };
    let outcome = if runtime_plugins {
        run_vfs_fixtures(&request)
    } else {
        let mut resolver = Fixtures { open_library: true };
        // SAFETY: the fixtures are native inputs using the production librs CRT.
        unsafe { run_linked(Input::Application, &mut resolver, &request) }.unwrap()
    };
    assert_eq!(outcome, ThreadGroupExit::Code(status));
    check_events(&output, expected_events);
}

fn run_vfs_fixtures(request: &RunRequest<'_>) -> ThreadGroupExit {
    let directory = c"/linked-fixtures";
    assert_eq!(vfs::syscalls::mkdir(directory.as_ptr(), 0o700), 0);
    let app = c"/linked-fixtures/linked-runtime.elf";
    // SAFETY: linker-provided fixture path pointers stay live throughout the test.
    let fixtures = unsafe {
        [
            (LINKED_TEST_APP_PATH, app),
            (
                LINKED_TEST_DSO_PATH,
                c"/linked-fixtures/liblinked_test_dso.so",
            ),
            (
                LINKED_TEST_PLUGIN_PATH,
                c"/linked-fixtures/linked-plugin.so",
            ),
        ]
    };
    for (source, path) in fixtures {
        let bytes = super::read_all(source).unwrap();
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
    // SAFETY: the VFS files stay immutable while either loader path reads them.
    let outcome = unsafe { run_linked_from_path(app.to_str().unwrap(), request) };
    for (_, path) in fixtures {
        assert_eq!(vfs::syscalls::unlink(path.as_ptr()), 0);
    }
    assert_eq!(vfs::syscalls::rmdir(directory.as_ptr()), 0);
    outcome.unwrap()
}
