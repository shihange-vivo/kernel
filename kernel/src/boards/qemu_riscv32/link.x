/* This code is derived from
 * https://github.com/eclipse-threadx/threadx/blob/master/ports/risc-v64/gnu/example_build/qemu_virt/link.lds
 * Copyright (c) 2024 - present Microsoft Corporation
 * SPDX-License-Identifier: MIT
 */

OUTPUT_ARCH("riscv")
ENTRY(_start)

/* Fixed-address firmware has no runtime relocations or lazy GOT binding. */
PHDRS
{
  text PT_LOAD FLAGS(5);   /* PF_R | PF_X */
  rodata PT_LOAD FLAGS(4); /* PF_R */
  data PT_LOAD FLAGS(6);   /* PF_R | PF_W */
}

SECTIONS
{
  /*
   * ensure that entry.S / _entry is at 0x80000000,
   * where qemu's -kernel jumps.
   */
  . = 0x80000000;

  /* Ignore build information, like .hash, .gnu.hash and etc. */

  .text : {
    . = ALIGN(16);
    *(.text._start)
    *(.text .text.*)
    . = ALIGN(0x1000);
    PROVIDE(etext = .);
  } :text

  .trap.handler : {
    *(.trap.handler .trap.handler.*)
  } :text

  .rodata (READONLY) : {
    . = ALIGN(16);
    *(.srodata .srodata.*) /* do not need to distinguish this from .rodata */
    . = ALIGN(16);
    *(.rodata .rodata.*)
    *(.data.rel.ro .data.rel.ro.* .sdata.rel.ro .sdata.rel.ro.*)
    *(.got .got.* .igot .igot.*)
  } :rodata

  /* Initialize C runtime. */
  /* .ctors and .dtors should not appear since we don't have C++ code at present. */
  .init_array (READONLY) : ALIGN(16) {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP (*(.init_array))
    PROVIDE_HIDDEN(__init_array_end = .);
  } :rodata

  .bk_app_array (READONLY) : ALIGN(16) {
    PROVIDE_HIDDEN(__bk_app_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.bk_app_array.*)))
    KEEP (*(.bk_app_array))
    PROVIDE_HIDDEN(__bk_app_array_end = .);
  } :rodata

  .eh_frame : {
    *(.eh_frame .eh_frame.*)
  } :rodata

  .data : {
    . = ALIGN(16);
    PROVIDE(__global_pointer$ = . + 0x800);
    *(.sdata .sdata.*) /* do not need to distinguish this from .data */
    . = ALIGN(16);
    *(.data .data.*)
  } :data

  .bss : {
    . = ALIGN(16);
    __bss_start = .;
    *(.sbss .sbss.*) /* do not need to distinguish this from .bss */
    . = ALIGN(16);
    *(.bss .bss.*)
    __bss_end = .;
  } :data

  .heap : {
    . = ALIGN(4096);
    __heap_start = .;
    . += 0x800000;
    __heap_end = .;
  } :data

  /* Ignore .fini_array since we are building a kernel which has no chance to
   * execute code in .fini_array. */

  .stack : {
    . = ALIGN(16);
    __sys_stack_start = .;
    . += 0x80000;
    __sys_stack_end = .;
  } :data

  PROVIDE(_end = .);
}
