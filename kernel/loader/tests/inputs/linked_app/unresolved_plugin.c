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

extern int missing_plugin_value(void);
extern void record_event(unsigned char event);

int (*const unresolved_plugin_value)(void) = missing_plugin_value;

static void init(int argc, char **argv, char **envp) {
  (void)argc;
  (void)argv;
  (void)envp;
  record_event('!');
}

__attribute__((used, section(".init_array"))) static void (*const constructor)(
    int, char **, char **) = init;

__attribute__((destructor)) static void fini(void) { record_event('?'); }
