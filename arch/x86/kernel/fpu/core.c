/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/processor.h>
#include <lego/kernel.h>
#include <asm/fpu/internal.h>

/*
 * Represents the initial FPU state. It's mostly (but not completely) zeroes,
 * depending on the FPU hardware format:
 */
union fpregs_state init_fpstate __read_mostly;

static inline void fpstate_init_fxstate(struct fxregs_state *fx)
{
	fx->cwd = 0x37f;
	fx->mxcsr = MXCSR_DEFAULT;
}

/*
 * Legacy x87 fpstate state init:
 */
static inline void fpstate_init_fstate(struct fregs_state *fp)
{
	fp->cwd = 0xffff037fu;
	fp->swd = 0xffff0000u;
	fp->twd = 0xffffffffu;
	fp->fos = 0xffff0000u;
}

void fpstate_init(union fpregs_state *state)
{
	if (!cpu_has(X86_FEATURE_FPU))
		return;

	memset(state, 0, fpu_kernel_xstate_size);

	/*
	 * XRSTORS requires that this bit is set in xcomp_bv, or
	 * it will #GP. Make sure it is replaced after the memset().
	 */
	if (cpu_has(X86_FEATURE_XSAVES))
		state->xsave.header.xcomp_bv = XCOMP_BV_COMPACTED_FORMAT |
					       xfeatures_mask;

	if (cpu_has(X86_FEATURE_FXSR))
		fpstate_init_fxstate(&state->fxsave);
	else
		fpstate_init_fstate(&state->fsave);
}
