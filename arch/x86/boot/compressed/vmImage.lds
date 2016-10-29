/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This file is included by all DisOS source files.
 * Because it is passed as a parameter into GCC.
 */
/*
 *
 * Automatically generated file; DO NOT EDIT.
 * DisOS/x86 0.0.1 Kernel Configuration
 *
 */
/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
/*
 * IS_REACHABLE(CONFIG_FOO) evaluates to 1 if the currently compiled
 * code can call a function defined in code compiled based on CONFIG_FOO.
 * This is similar to IS_ENABLED(), but returns false when invoked from
 * built-in code when CONFIG_FOO is set to 'm'.
 */
/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */
/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */
/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Macros for dealing with constants.
 */
/*
 * Some constant macros are used in both assembler and
 * C code. Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally. We use
 * the following macros to deal with this.
 *
 * Similarly, _AT() will cast an expression with a type in C, but
 * leave it unchanged in asm.
 */
/*
 * x86-64
 *
 * Set __PAGE_OFFSET to the most negative possible address +
 * PGDIR_SIZE*16 (pgd slot 272).  The gap is to allow a space for a
 * hypervisor to fit.  Choosing 16 slots here is arbitrary, but it's
 * what Xen requires.
 */
/* See Documentation/x86/x86_64/mm.txt for a description of the memory map. */
OUTPUT_ARCH(i386:x86-64)
ENTRY(startup_64)
SECTIONS
{
 /*
	 * Be careful parts of head_64.S assume startup_32 is at
	 * address 0.
	 */
 . = 0;
 .head.text : {
  _head = .;
  *(.head.text)
  _ehead = .;
 }
 . = ALIGN((1 << 12));
 .compressed_kernel : {
  _kernel = .;
  *(.compressed_kernel)
  _ekernel = .;
 }
 . = ALIGN((1 << 12));
 .text : {
  _text = .;
  *(.text*)
  _etext = .;
 }
 .rodata : {
  _rodata = .;
  *(.rodata*)
  _erodata = .;
 }
 .data : {
  _data = .;
  *(.data*)
  _edata = .;
 }
 . = ALIGN(64);
 .bss : {
  _bss = .;
  *(.bss*)
  _ebss = .;
 }
       . = ALIGN((1 << 12));
       .pgtable : {
  _pgtable = .;
  *(.pgtable)
  _epgtable = .;
 }
 _end = .;
}
