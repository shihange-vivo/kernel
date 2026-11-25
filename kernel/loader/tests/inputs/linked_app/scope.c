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

extern void record_event(unsigned char event);
extern int scope_cpp_tick(void);
extern int absent_function(void) __attribute__((weak));
extern int absent_data __attribute__((weak));

static const int initial_count = 10;
static struct EmutlsControl counter = {
    sizeof(int), _Alignof(int), {0}, &initial_count};

__attribute__((visibility("protected"))) int linked_choice(void) { return 33; }

__attribute__((visibility("hidden"))) int scope_hidden(void) { return 7; }

int scope_check(void) {
  return absent_function == 0 && &absent_data == 0 && linked_choice() == 33 &&
         scope_hidden() == 7;
}

int scope_tick(void) {
  int *value = __emutls_get_address(&counter);
  return 100 * ++*value + scope_cpp_tick();
}

static void init(int argc, char **argv, char **envp) {
  (void)argc;
  (void)argv;
  (void)envp;
  record_event('S');
}

__attribute__((used, section(".init_array"))) static void (*const constructor)(
    int, char **, char **) = init;

__attribute__((destructor)) static void fini(void) { record_event('s'); }
