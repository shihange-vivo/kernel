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

//! Decode the trusted kernel test's gate arguments without reading the gate.

use core::{
    ffi::{c_char, c_int, CStr},
    sync::atomic::AtomicUsize,
};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum TestGate {
    NotRequested,
    Invalid,
    Address(*const AtomicUsize),
}

/// Accept the kernel harness's unprefixed hexadecimal address format.
/// Null and alignment checks do not establish that the address is readable;
/// the caller that uses the gate must guarantee its backing and lifetime.
fn parse_address(bytes: &[u8]) -> Option<*const AtomicUsize> {
    if bytes.is_empty() {
        return None;
    }
    let mut address = 0usize;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        address = address.checked_mul(16)?.checked_add(usize::from(digit))?;
    }
    let pointer = address as *const AtomicUsize;
    if pointer.is_null() || !pointer.is_aligned() {
        return None;
    }
    Some(pointer)
}

/// Decode the optional gate without dereferencing a numeric address.
///
/// # Safety
/// For `argc == 3`, a non-null `argv` must contain at least three initialized
/// pointers. Each non-null string inspected must be readable through its NUL
/// byte and remain valid and unmodified during this call.
pub(super) unsafe fn from_argv(argc: c_int, argv: *const *const c_char) -> TestGate {
    if argc < 0 || (argc > 0 && argv.is_null()) {
        return TestGate::Invalid;
    }
    if argc != 3 {
        return TestGate::NotRequested;
    }
    let flag = unsafe { *argv.add(1) };
    if flag.is_null() {
        return TestGate::Invalid;
    }
    if unsafe { CStr::from_ptr(flag).to_bytes() } != b"--test-gate" {
        return TestGate::NotRequested;
    }
    let value = unsafe { *argv.add(2) };
    if value.is_null() {
        return TestGate::Invalid;
    }
    match parse_address(unsafe { CStr::from_ptr(value).to_bytes() }) {
        Some(pointer) => TestGate::Address(pointer),
        None => TestGate::Invalid,
    }
}
