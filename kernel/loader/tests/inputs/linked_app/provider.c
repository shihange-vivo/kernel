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

extern void record_event(unsigned char event);

int linked_data;

static void init(int argc, char **argv, char **envp) {
  (void)argc;
  (void)argv;
  (void)envp;
  linked_data = 21;
  record_event('D');
}

__attribute__((used, section(".init_array")))
static void (*const constructor)(int, char **, char **) = init;

__attribute__((destructor)) static void fini(void) {
  record_event('d');
}

int linked_value(void) { return linked_data * 2; }

int linked_choice(void) { return 1; }
