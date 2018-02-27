/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_EXTABLE_H_
#define _ASM_X86_EXTABLE_H_

/*
 * The exception table consists of triples of addresses relative to the
 * exception table entry itself. The first address is of an instruction
 * that is allowed to fault, the second is the target at which the program
 * should continue. The third is a handler function to deal with the fault
 * caused by the instruction in the first field.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

#ifndef __ASSEMBLY__
struct exception_table_entry {
	int	insn;		/* An instruction that is allowed to fault */
	int	fixup;		/* target where program should continue */
	int	handler;	/* handler to deal with the fault cause by @insn */
};

#define ARCH_HAS_RELATIVE_EXTABLE

#define swap_ex_entry_fixup(a, b, tmp, delta)			\
	do {							\
		(a)->fixup = (b)->fixup + (delta);		\
		(b)->fixup = (tmp).fixup - (delta);		\
		(a)->handler = (b)->handler + (delta);		\
		(b)->handler = (tmp).handler - (delta);		\
	} while (0)

struct pt_regs;
int fixup_exception(struct pt_regs *regs, int trapnr);
bool ex_has_fault_handler(unsigned long ip);
void early_fixup_exception(struct pt_regs *regs, int trapnr);
#endif

/* Exception table entry */
#ifdef __ASSEMBLY__
# define _ASM_EXTABLE_HANDLE(from, to, handler)			\
	.pushsection "__ex_table","a" ;				\
	.balign 4 ;						\
	.long (from) - . ;					\
	.long (to) - . ;					\
	.long (handler) - . ;					\
	.popsection

# define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_default)

# define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_fault)

# define _ASM_EXTABLE_EX(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_ext)

.macro ALIGN_DESTINATION
	/* check for bad alignment of destination */
	movl %edi,%ecx
	andl $7,%ecx
	jz 102f				/* already aligned */
	subl $8,%ecx
	negl %ecx
	subl %ecx,%edx
100:	movb (%rsi),%al
101:	movb %al,(%rdi)
	incq %rsi
	incq %rdi
	decl %ecx
	jnz 100b
102:
	.section .fixup,"ax"
103:	addl %ecx,%edx			/* ecx is zerorest also */
	jmp copy_user_handle_tail
	.previous

	_ASM_EXTABLE(100b,103b)
	_ASM_EXTABLE(101b,103b)
.endm
#else /* !__ASSEMBLY__ */
# define _EXPAND_EXTABLE_HANDLE(x) #x
# define _ASM_EXTABLE_HANDLE(from, to, handler)			\
	" .pushsection \"__ex_table\",\"a\"\n"			\
	" .balign 4\n"						\
	" .long (" #from ") - .\n"				\
	" .long (" #to ") - .\n"				\
	" .long (" _EXPAND_EXTABLE_HANDLE(handler) ") - .\n"	\
	" .popsection\n"

# define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_default)

# define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_fault)

# define _ASM_EXTABLE_EX(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_ext)
#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_EXTABLE_H_ */
