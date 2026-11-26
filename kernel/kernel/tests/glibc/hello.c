/*
 * Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

static _Thread_local volatile int tls_value = 7;

__attribute__((constructor)) static void init(void) { tls_value += 35; }

static long unknown_svc(void) {
  register long result asm("x0") = 0;
  register unsigned long number asm("x8") = -1;
  asm volatile("svc #0" : "+r"(result) : "r"(number) : "memory");
  return result;
}

int main(int argc, char **argv) {
  static const char message[] = "hello from BlueKernel glibc\n";
  if (argc != 1 || strcmp(argv[0], "/glibc-hello") != 0)
    return 1;
  if (tls_value != 42 || getauxval(AT_BASE) == 0 || getauxval(AT_RANDOM) == 0)
    return 2;
  char *buffer = malloc(sizeof(message));
  if (buffer == NULL)
    return 3;
  memcpy(buffer, message, sizeof(message));
  ssize_t written = write(STDOUT_FILENO, buffer, sizeof(message) - 1);
  free(buffer);
  if (written != (ssize_t)(sizeof(message) - 1))
    return 4;
  if (syscall(-1) != -1 || errno != ENOSYS)
    return 5;
  if (unknown_svc() != -ENOSYS)
    return 6;
  return tls_value;
}
