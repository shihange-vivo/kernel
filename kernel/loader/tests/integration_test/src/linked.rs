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
        load_request, prepare_linked, run_linked, RunRequest,
    },
    thread_group::{StandardIo, ThreadGroupExit, ThreadGroupState},
    vfs,
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
    check_launch(c"LINK_TEST=normal", 42, b"PDIMFd");
}

#[test]
fn test_linked_thread_group_retires_after_exit_from_a_constructor() {
    check_launch(c"LINK_TEST=abort", 19, b"PD");
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

fn check_launch(env: &CStr, status: i32, expected_events: &[u8]) {
    let (output, stdio) = capture_output("/linked-output");
    let request = RunRequest {
        envp: &[env],
        stdio: Some(&stdio),
        ..RunRequest::default()
    };
    // SAFETY: the fixtures are native ELF inputs using the production librs CRT.
    let outcome = unsafe {
        run_linked(
            Input::Application,
            &mut Fixtures { open_library: true },
            &request,
        )
    }
    .unwrap();
    assert_eq!(outcome, ThreadGroupExit::Code(status));
    check_events(&output, expected_events);
}
