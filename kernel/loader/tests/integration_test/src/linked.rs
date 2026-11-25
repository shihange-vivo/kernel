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
        load_request, run_linked, RunRequest,
    },
    thread_group::{StandardIo, ThreadGroupExit},
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

fn check_launch(env: &CStr, status: i32, expected_events: &[u8]) {
    let output = Arc::new(
        vfs::open_path(
            "/linked-output",
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR,
            0o600,
        )
        .unwrap(),
    );
    let stdio = StandardIo {
        stdin: output.clone(),
        stdout: output.clone(),
        stderr: output.clone(),
    };
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
    let mut events = [0; 8];
    let count = output.read_at(0, &mut events).unwrap();
    assert_eq!(&events[..count], expected_events);
}
