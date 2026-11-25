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

extern int linked_value(void);
extern int linked_data;
extern int linked_choice(void);
extern void record_event(unsigned char event);

int (*const plugin_value)(void) = linked_value;
int *const plugin_data = &linked_data;
int (*const plugin_choice)(void) = linked_choice;

static void init(int argc, char **argv, char **envp) {
  /* Runtime opens pass the original application arguments to constructors. */
  if (!argv || !envp || !envp[0] ||
      (envp[0][sizeof("LINK_TEST=") - 1] == 'r' &&
       (argc != 2 || !argv[0] || !argv[1] || argv[1][0] != 't' || argv[2]))) {
    record_event('?');
    return;
  }
  ++*plugin_data;
  record_event(plugin_choice() == 2 && plugin_value() == 44 ? 'L' : '?');
}

__attribute__((used, section(".init_array")))
static void (*const constructor)(int, char **, char **) = init;

__attribute__((destructor)) static void fini(void) {
  record_event('l');
}
