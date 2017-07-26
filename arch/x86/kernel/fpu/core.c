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
#include <asm/fpu/internal.h>

#include <lego/sched.h>
#include <lego/percpu.h>
#include <lego/kernel.h>

/*
 * Represents the initial FPU state. It's mostly (but not completely) zeroes,
 * depending on the FPU hardware format:
 */
union fpregs_state init_fpstate __read_mostly;

/*
 * Track which context is using the FPU on the CPU:
 */
DEFINE_PER_CPU(struct fpu *, fpu_fpregs_owner_ctx);

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

int fpu__copy(struct fpu *dst_fpu, struct fpu *src_fpu)
{
	dst_fpu->counter = 0;
	dst_fpu->fpregs_active = 0;
	dst_fpu->last_cpu = -1;

	if (!src_fpu->fpstate_active || !cpu_has(X86_FEATURE_FPU))
		return 0;

	WARN_ON_FPU(src_fpu != &current->thread.fpu);

	/*
	 * Don't let 'init optimized' areas of the XSAVE area
	 * leak into the child task:
	 */
	if (use_eager_fpu())
		memset(&dst_fpu->state.xsave, 0, fpu_kernel_xstate_size);

	/*
	 * Save current FPU registers directly into the child
	 * FPU context, without any memory-to-memory copying.
	 * In lazy mode, if the FPU context isn't loaded into
	 * fpregs, CR0.TS will be set and do_device_not_available
	 * will load the FPU context.
	 *
	 * We have to do all this with preemption disabled,
	 * mostly because of the FNSAVE case, because in that
	 * case we must not allow preemption in the window
	 * between the FNSAVE and us marking the context lazy.
	 *
	 * It shouldn't be an issue as even FNSAVE is plenty
	 * fast in terms of critical section length.
	 */
	preempt_disable();
	if (!copy_fpregs_to_fpstate(dst_fpu)) {
		memcpy(&src_fpu->state, &dst_fpu->state,
		       fpu_kernel_xstate_size);

		if (use_eager_fpu())
			copy_kernel_to_fpregs(&src_fpu->state);
		else
			fpregs_deactivate(src_fpu);
	}
	preempt_enable();

	return 0;
}

/*
 * Activate the current task's in-memory FPU context,
 * if it has not been used before:
 */
void fpu__activate_curr(struct fpu *fpu)
{
	WARN_ON_FPU(fpu != &current->thread.fpu);

	if (!fpu->fpstate_active) {
		fpstate_init(&fpu->state);

		/* Safe to do for the current task: */
		fpu->fpstate_active = 1;
	}
}

/*
 * 'fpu__restore()' is called to copy FPU registers from
 * the FPU fpstate to the live hw registers and to activate
 * access to the hardware registers, so that FPU instructions
 * can be used afterwards.
 *
 * Must be called with kernel preemption disabled (for example
 * with local interrupts disabled, as it is in the case of
 * do_device_not_available()).
 */
void fpu__restore(struct fpu *fpu)
{
	fpu__activate_curr(fpu);

	/* Avoid __kernel_fpu_begin() right after fpregs_activate() */
	fpregs_activate(fpu);
	copy_kernel_to_fpregs(&fpu->state);
	fpu->counter++;
}

/*
 * Clear FPU registers by setting them up from
 * the init fpstate:
 */
static inline void copy_init_fpstate_to_fpregs(void)
{
	if (use_xsave())
		copy_kernel_to_xregs(&init_fpstate.xsave, -1);
	else if (cpu_has(X86_FEATURE_FXSR))
		copy_kernel_to_fxregs(&init_fpstate.fxsave);
	else
		copy_kernel_to_fregs(&init_fpstate.fsave);
}

/*
 * Drops current FPU state: deactivates the fpregs and
 * the fpstate. NOTE: it still leaves previous contents
 * in the fpregs in the eager-FPU case.
 *
 * This function can be used in cases where we know that
 * a state-restore is coming: either an explicit one,
 * or a reschedule.
 */
void fpu__drop(struct fpu *fpu)
{
	preempt_disable();
	fpu->counter = 0;

	if (fpu->fpregs_active) {
		/* Ignore delayed exceptions from user space */
		asm volatile("1: fwait\n"
			     "2:\n"
			     _ASM_EXTABLE(1b, 2b));
		fpregs_deactivate(fpu);
	}

	fpu->fpstate_active = 0;

	preempt_enable();
}

/*
 * Clear the FPU state back to init state.
 *
 * Called by sys_execve(), by the signal handler code and by various
 * error paths.
 */
void fpu__clear(struct fpu *fpu)
{
	WARN_ON_FPU(fpu != &current->thread.fpu); /* Almost certainly an anomaly */

	fpu__drop(fpu);

	/*
	 * Make sure fpstate is cleared and initialized.
	 */
	if (cpu_has(X86_FEATURE_FPU)) {
		fpu__activate_curr(fpu);
		user_fpu_begin();
		copy_init_fpstate_to_fpregs();
	}
}

