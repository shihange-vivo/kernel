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

#![no_std]
extern "C" {
    fn dl_runtime_provider() -> usize;
}
#[no_mangle]
pub extern "C" fn dl_consumer_value() -> usize {
    // SAFETY: the fixture export is extern C fn() -> usize. Its relocation
    // retains the selected provider through this consumer's lifetime.
    let value = unsafe { dl_runtime_provider() };
    value + 7
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
