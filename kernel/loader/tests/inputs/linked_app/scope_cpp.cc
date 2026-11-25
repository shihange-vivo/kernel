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

#include "emutls_counter.h"

extern "C" void record_event(unsigned char event);

namespace {
const int initial_count = 20;
EmutlsControl counter = {sizeof(int), alignof(int), {0}, &initial_count};

class State {
public:
  State() : value(1) { record_event('Q'); }
  int value;
};

State state;
} // namespace

extern "C" int scope_cpp_tick() {
  auto *value = static_cast<int *>(__emutls_get_address(&counter));
  return ++*value + state.value;
}

__attribute__((destructor)) static void fini() { record_event('q'); }
