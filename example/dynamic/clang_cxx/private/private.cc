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

// Private C++ DSO used by the clang_cxx dynamic-loading fixture.
// Its constructor sets private_state to 37 before the application's main;
// the exported C ABI accessor reads that state through PrivateValue.
// Constructor/destructor logs let the integration test verify one-time
// initialization and finalization while the DSO remains mapped. This DSO
// shares libc.so.1 with the root and uses no separate C++ runtime library.

extern "C" int printf(const char *format, ...);

namespace {

int private_state;

class PrivateValue {
public:
  explicit constexpr PrivateValue(int base) : base_(base) {}

  constexpr int add(int value) const { return base_ + value; }

private:
  int base_;
};

__attribute__((constructor)) void initializePrivate() {
  private_state = 37;
  printf("clang-cxx: private ctor state=%d\n", private_state);
}

__attribute__((destructor)) void finalizePrivate() {
  printf("clang-cxx: private fini state=%d\n", private_state);
}

} // namespace

extern "C" int clangCxxPrivateValue(int input) {
  return PrivateValue(private_state).add(input);
}
