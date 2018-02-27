/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_x86_UCONTEXT_H_
#define _ASM_x86_UCONTEXT_H_

#include <asm/signal.h>
#include <asm/sigcontext.h>
#include <asm/processor-features.h>

typedef struct sigaltstack {
	void __user *ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_t;

struct ucontext {
	unsigned long	  uc_flags;
	struct ucontext  *uc_link;
	stack_t		  uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t	  uc_sigmask;	/* mask last for extensibility */
};

/*
 * Indicates the presence of extended state information in the memory
 * layout pointed by the fpstate pointer in the ucontext's sigcontext
 * struct (uc_mcontext).
 */
#define UC_FP_XSTATE	0x1

/*
 * UC_SIGCONTEXT_SS will be set when delivering 64-bit or x32 signals on
 * kernels that save SS in the sigcontext.  All kernels that set
 * UC_SIGCONTEXT_SS will correctly restore at least the low 32 bits of esp
 * regardless of SS (i.e. they implement espfix).
 *
 * Kernels that set UC_SIGCONTEXT_SS will also set UC_STRICT_RESTORE_SS
 * when delivering a signal that came from 64-bit code.
 *
 * Sigreturn restores SS as follows:
 *
 * if (saved SS is valid || UC_STRICT_RESTORE_SS is set ||
 *     saved CS is not 64-bit)
 *         new SS = saved SS  (will fail IRET and signal if invalid)
 * else
 *         new SS = a flat 32-bit data segment
 *
 * This behavior serves three purposes:
 *
 * - Legacy programs that construct a 64-bit sigcontext from scratch
 *   with zero or garbage in the SS slot (e.g. old CRIU) and call
 *   sigreturn will still work.
 *
 * - Old DOSEMU versions sometimes catch a signal from a segmented
 *   context, delete the old SS segment (with modify_ldt), and change
 *   the saved CS to a 64-bit segment.  These DOSEMU versions expect
 *   sigreturn to send them back to 64-bit mode without killing them,
 *   despite the fact that the SS selector when the signal was raised is
 *   no longer valid.  UC_STRICT_RESTORE_SS will be clear, so the kernel
 *   will fix up SS for these DOSEMU versions.
 *
 * - Old and new programs that catch a signal and return without
 *   modifying the saved context will end up in exactly the state they
 *   started in, even if they were running in a segmented context when
 *   the signal was raised..  Old kernels would lose track of the
 *   previous SS value.
 */
#define UC_SIGCONTEXT_SS	0x2
#define UC_STRICT_RESTORE_SS	0x4

#endif /* _ASM_x86_UCONTEXT_H_ */
