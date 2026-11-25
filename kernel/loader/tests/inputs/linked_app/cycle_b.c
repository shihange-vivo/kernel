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

extern int cycle_a_value(void);
extern void record_event(unsigned char event);

static int value;

static void init(int argc, char **argv, char **envp) {
  (void)argc;
  (void)argv;
  (void)envp;
  value = cycle_a_value() + 4;
  record_event('B');
}

__attribute__((used, section(".init_array"))) static void (*const constructor)(
    int, char **, char **) = init;

__attribute__((destructor)) static void fini(void) {
  record_event(cycle_a_value() == 11 && value == 15 ? 'b' : '?');
  value = 0;
}

int cycle_b_value(void) { return value; }

int cycle_b_call_a(void) { return cycle_a_value() + value; }
