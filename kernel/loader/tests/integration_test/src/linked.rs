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
    loader::{run_linked, RunRequest},
    thread_group::{StandardIo, ThreadGroupExit},
    vfs,
};
use blueos_loader::{
    dynamic_linker::DependencyResolver,
    error::{ErrorContext, LoadErrorKind},
    LoadError, LoadResult,
};
use blueos_test_macro::test;
use core::ffi::{c_char, CStr};

unsafe extern "C" {
    static LINKED_TEST_APP_PATH: *const c_char;
    static LINKED_TEST_DSO_PATH: *const c_char;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Input {
    Application,
    Library,
}

struct Fixtures;

impl DependencyResolver for Fixtures {
    type Key = Input;
    type Reader = FileReader;

    fn resolve(&mut self, requester: &Input, name: &[u8]) -> LoadResult<Input> {
        if *requester == Input::Application && name == b"liblinked_test_dso.so" {
            return Ok(Input::Library);
        }
        Err(LoadError::new(LoadErrorKind::Io, ErrorContext::None))
    }

    fn open(&mut self, key: &Input) -> LoadResult<Self::Reader> {
        // SAFETY: these linker-provided pointers name live host fixture paths.
        let path = unsafe {
            CStr::from_ptr(match key {
                Input::Application => LINKED_TEST_APP_PATH,
                Input::Library => LINKED_TEST_DSO_PATH,
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
    let outcome = unsafe { run_linked(Input::Application, &mut Fixtures, &request) }.unwrap();
    assert_eq!(outcome, ThreadGroupExit::Code(status));
    let mut events = [0; 8];
    let count = output.read_at(0, &mut events).unwrap();
    assert_eq!(&events[..count], expected_events);
}
