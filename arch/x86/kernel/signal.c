/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/signal.h>
#include <lego/syscalls.h>

#include <asm/desc.h>
#include <asm/sigframe.h>
#include <asm/sigcontext.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <generated/unistd_64.h>

#define COPY(x)			do {			\
	get_user_ex(regs->x, &sc->x);			\
} while (0)

#define GET_SEG(seg)		({			\
	unsigned short tmp;				\
	get_user_ex(tmp, &sc->seg);			\
	tmp;						\
})

#define COPY_SEG(seg)		do {			\
	regs->seg = GET_SEG(seg);			\
} while (0)

#define COPY_SEG_CPL3(seg)	do {			\
	regs->seg = GET_SEG(seg) | 3;			\
} while (0)

static inline bool user_64bit_mode(struct pt_regs *regs)
{
	/*
	 * On non-paravirt systems, this is the only long mode CPL 3
	 * selector.  We do not allow long mode selectors in the LDT.
	 */
	return regs->cs == __USER_CS;
}

/*
 * If regs->ss will cause an IRET fault, change it.  Otherwise leave it
 * alone.  Using this generally makes no sense unless
 * user_64bit_mode(regs) would return true.
 */
static void force_valid_ss(struct pt_regs *regs)
{
	u32 ar;
	asm volatile ("lar %[old_ss], %[ar]\n\t"
		      "jz 1f\n\t"		/* If invalid: */
		      "xorl %[ar], %[ar]\n\t"	/* set ar = 0 */
		      "1:"
		      : [ar] "=r" (ar)
		      : [old_ss] "rm" ((u16)regs->ss));

	/*
	 * For a valid 64-bit user context, we need DPL 3, type
	 * read-write data or read-write exp-down data, and S and P
	 * set.  We can't use VERW because VERW doesn't check the
	 * P bit.
	 */
	ar &= AR_DPL_MASK | AR_S | AR_P | AR_TYPE_MASK;
	if (ar != (AR_DPL3 | AR_S | AR_P | AR_TYPE_RWDATA) &&
	    ar != (AR_DPL3 | AR_S | AR_P | AR_TYPE_RWDATA_EXPDOWN))
		regs->ss = __USER_DS;
}

#define FIX_EFLAGS	(X86_EFLAGS_AC | X86_EFLAGS_OF | \
			 X86_EFLAGS_DF | X86_EFLAGS_TF | X86_EFLAGS_SF | \
			 X86_EFLAGS_ZF | X86_EFLAGS_AF | X86_EFLAGS_PF | \
			 X86_EFLAGS_CF | X86_EFLAGS_RF)

static int restore_sigcontext(struct pt_regs *regs,
			      struct sigcontext __user *sc,
			      unsigned long uc_flags)
{
	unsigned long buf_val;
	void __user *buf;
	unsigned int tmpflags;
	unsigned int err = 0;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	get_user_try {

		COPY(di); COPY(si); COPY(bp); COPY(sp); COPY(bx);
		COPY(dx); COPY(cx); COPY(ip); COPY(ax);

		COPY(r8);
		COPY(r9);
		COPY(r10);
		COPY(r11);
		COPY(r12);
		COPY(r13);
		COPY(r14);
		COPY(r15);

		COPY_SEG_CPL3(cs);
		COPY_SEG_CPL3(ss);

		/*
		 * Fix up SS if needed for the benefit of old DOSEMU and
		 * CRIU.
		 */
		if (unlikely(!(uc_flags & UC_STRICT_RESTORE_SS) &&
			     user_64bit_mode(regs)))
			force_valid_ss(regs);

		get_user_ex(tmpflags, &sc->flags);
		regs->flags = (regs->flags & ~FIX_EFLAGS) | (tmpflags & FIX_EFLAGS);
		regs->orig_ax = -1;		/* disable syscall checks */

		get_user_ex(buf_val, &sc->fpstate);
		buf = (void __user *)buf_val;
	} get_user_catch(err);

	err |= fpu__restore_sig(buf, IS_ENABLED(CONFIG_X86_32));

	force_iret();

	return err;
}

int setup_sigcontext(struct sigcontext __user *sc, void __user *fpstate,
		     struct pt_regs *regs, unsigned long mask)
{
	int err = 0;

	put_user_try {

		put_user_ex(regs->di, &sc->di);
		put_user_ex(regs->si, &sc->si);
		put_user_ex(regs->bp, &sc->bp);
		put_user_ex(regs->sp, &sc->sp);
		put_user_ex(regs->bx, &sc->bx);
		put_user_ex(regs->dx, &sc->dx);
		put_user_ex(regs->cx, &sc->cx);
		put_user_ex(regs->ax, &sc->ax);
		put_user_ex(regs->r8, &sc->r8);
		put_user_ex(regs->r9, &sc->r9);
		put_user_ex(regs->r10, &sc->r10);
		put_user_ex(regs->r11, &sc->r11);
		put_user_ex(regs->r12, &sc->r12);
		put_user_ex(regs->r13, &sc->r13);
		put_user_ex(regs->r14, &sc->r14);
		put_user_ex(regs->r15, &sc->r15);

		put_user_ex(current->thread.trap_nr, &sc->trapno);
		put_user_ex(current->thread.error_code, &sc->err);
		put_user_ex(regs->ip, &sc->ip);
		put_user_ex(regs->flags, &sc->flags);
		put_user_ex(regs->cs, &sc->cs);
		put_user_ex(0, &sc->gs);
		put_user_ex(0, &sc->fs);
		put_user_ex(regs->ss, &sc->ss);

		put_user_ex(fpstate, &sc->fpstate);

		/* non-iBCS2 extensions.. */
		put_user_ex(mask, &sc->oldmask);
		put_user_ex(current->thread.cr2, &sc->cr2);
	} put_user_catch(err);

	return err;
}

/*
 * Set up a signal frame.
 */

static unsigned long align_sigframe(unsigned long sp)
{
	sp = round_down(sp, 16) - 8;
	return sp;
}

static void __user *
get_sigframe(struct k_sigaction *ka, struct pt_regs *regs, size_t frame_size,
	     void __user **fpstate)
{
	/* Default to using normal stack */
	unsigned long math_size = 0;
	unsigned long sp = regs->sp;
	unsigned long buf_fx = 0;
	int onsigstack = on_sig_stack(sp);
	struct fpu *fpu = &current->thread.fpu;

	/* redzone */
	sp -= 128;

	/* This is the X/Open sanctioned signal stack switching.  */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (sas_ss_flags(sp) == 0)
			sp = current->sas_ss_sp + current->sas_ss_size;
	}

	if (fpu->fpstate_active) {
		sp = fpu__alloc_mathframe(sp, IS_ENABLED(CONFIG_X86_32),
					  &buf_fx, &math_size);
		*fpstate = (void __user *)sp;
	}

	sp = align_sigframe(sp - frame_size);

	/*
	 * If we are on the alternate signal stack and would overflow it, don't.
	 * Return an always-bogus address instead so we will die with SIGSEGV.
	 */
	if (onsigstack && !likely(on_sig_stack(sp)))
		return (void __user *)-1L;

	/* save i387 and extended state */
	if (fpu->fpstate_active &&
	    copy_fpstate_to_sigframe(*fpstate, (void __user *)buf_fx, math_size) < 0)
		return (void __user *)-1L;

	return (void __user *)sp;
}

static unsigned long frame_uc_flags(struct pt_regs *regs)
{
	unsigned long flags;

	if (cpu_has(X86_FEATURE_XSAVE))
		flags = UC_FP_XSTATE | UC_SIGCONTEXT_SS;
	else
		flags = UC_SIGCONTEXT_SS;

	if (likely(user_64bit_mode(regs)))
		flags |= UC_STRICT_RESTORE_SS;

	return flags;
}

static int __setup_rt_frame(int sig, struct ksignal *ksig,
			    sigset_t *set, struct pt_regs *regs)
{
	struct rt_sigframe __user *frame;
	void __user *fp = NULL;
	int err = 0;

	frame = get_sigframe(&ksig->ka, regs, sizeof(struct rt_sigframe), &fp);

	if (!access_ok(VERIFY_WRITE, frame, sizeof(*frame)))
		return -EFAULT;

	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		if (copy_siginfo_to_user(&frame->info, &ksig->info))
			return -EFAULT;
	}

	put_user_try {
		/* Create the ucontext.  */
		put_user_ex(frame_uc_flags(regs), &frame->uc.uc_flags);
		put_user_ex(0, &frame->uc.uc_link);
		save_altstack_ex(&frame->uc.uc_stack, regs->sp);

		/* Set up to return from userspace.  If provided, use a stub
		   already in userspace.  */
		/* x86-64 should always use SA_RESTORER. */
		if (ksig->ka.sa.sa_flags & SA_RESTORER) {
			put_user_ex(ksig->ka.sa.sa_restorer, &frame->pretcode);
		} else {
			/* could use a vstub here */
			err |= -EFAULT;
		}
	} put_user_catch(err);

	err |= setup_sigcontext(&frame->uc.uc_mcontext, fp, regs, set->sig[0]);
	err |= __copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));

	if (err)
		return -EFAULT;

	/* Set up registers for signal handler */
	regs->di = sig;
	/* In case the signal handler was declared without prototypes */
	regs->ax = 0;

	/* This also works for non SA_SIGINFO handlers because they expect the
	   next argument after the signal number on the stack. */
	regs->si = (unsigned long)&frame->info;
	regs->dx = (unsigned long)&frame->uc;
	regs->ip = (unsigned long)ksig->ka.sa.sa_handler;
	regs->sp = (unsigned long)frame;

	/*
	 * Set up the CS and SS registers to run signal handlers in
	 * 64-bit mode, even if the handler happens to be interrupting
	 * 32-bit or 16-bit code.
	 *
	 * SS is subtle.  In 64-bit mode, we don't need any particular
	 * SS descriptor, but we do need SS to be valid.  It's possible
	 * that the old SS is entirely bogus -- this can happen if the
	 * signal we're trying to deliver is #GP or #SS caused by a bad
	 * SS value.  We also have a compatbility issue here: DOSEMU
	 * relies on the contents of the SS register indicating the
	 * SS value at the time of the signal, even though that code in
	 * DOSEMU predates sigreturn's ability to restore SS.  (DOSEMU
	 * avoids relying on sigreturn to restore SS; instead it uses
	 * a trampoline.)  So we do our best: if the old SS was valid,
	 * we keep it.  Otherwise we replace it.
	 */
	regs->cs = __USER_CS;

	if (unlikely(regs->ss != __USER_DS))
		force_valid_ss(regs);

	return 0;
}

static int
setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
{
	sigset_t *set = sigmask_to_save();
	return __setup_rt_frame(ksig->sig, ksig, set, regs);
}

static void
handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	bool stepping, failed;
	struct fpu *fpu = &current->thread.fpu;

	/* Are we from a system call? */
	if (syscall_get_nr(current, regs) >= 0) {
		/* If so, check system call restarting.. */
		switch (syscall_get_error(current, regs)) {
		case -ERESTART_RESTARTBLOCK:
		case -ERESTARTNOHAND:
			regs->ax = -EINTR;
			break;

		case -ERESTARTSYS:
			if (!(ksig->ka.sa.sa_flags & SA_RESTART)) {
				regs->ax = -EINTR;
				break;
			}
		/* fallthrough */
		case -ERESTARTNOINTR:
			regs->ax = regs->orig_ax;
			regs->ip -= 2;
			break;
		}
	}

	/*
	 * If TF is set due to a debugger (TIF_FORCED_TF), clear TF now
	 * so that register information in the sigcontext is correct and
	 * then notify the tracer before entering the signal handler.
	 */
	stepping = test_thread_flag(TIF_SINGLESTEP);

	failed = (setup_rt_frame(ksig, regs) < 0);
	if (!failed) {
		/*
		 * Clear the direction flag as per the ABI for function entry.
		 *
		 * Clear RF when entering the signal handler, because
		 * it might disable possible debug exception from the
		 * signal handler.
		 *
		 * Clear TF for the case when it wasn't set by debugger to
		 * avoid the recursive send_sigtrap() in SIGTRAP handler.
		 */
		regs->flags &= ~(X86_EFLAGS_DF|X86_EFLAGS_RF|X86_EFLAGS_TF);
		/*
		 * Ensure the signal handler starts with the new fpu state.
		 */
		if (fpu->fpstate_active)
			fpu__clear(fpu);
	}
	signal_setup_done(failed, ksig, stepping);
}

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 */
void do_signal(struct pt_regs *regs)
{
	struct ksignal ksig;

	if (get_signal(&ksig)) {
		/* Whee! Actually deliver the signal.  */
		pr_info("%s(): sig: %d\n", FUNC, ksig.sig);
		handle_signal(&ksig, regs);
		return;
	}

	/* Did we come from a system call? */
	if (syscall_get_nr(current, regs) >= 0) {
		/* Restart the system call - no handlers present */
		switch (syscall_get_error(current, regs)) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs->ax = regs->orig_ax;
			regs->ip -= 2;
			break;

		case -ERESTART_RESTARTBLOCK:
			regs->ax = __NR_restart_syscall;
			regs->ip -= 2;
			break;
		}
	}

	/*
	 * If there's no signal to deliver,
	 * we just put the saved sigmask back.
	 */
	restore_saved_sigmask();
}

void signal_fault(struct pt_regs *regs, void __user *frame, char *where)
{
	struct task_struct *me = current;

	printk("%s[%d] bad frame in %s frame:%p ip:%lx sp:%lx orax:%lx",
	       me->comm, me->pid, where, frame,
	       regs->ip, regs->sp, regs->orig_ax);
	pr_cont("\n");

	force_sig(SIGSEGV, me);
}

SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe __user *frame;
	sigset_t set;
	unsigned long uc_flags;

	frame = (struct rt_sigframe __user *)(regs->sp - sizeof(long));
	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)))
		goto badframe;
	if (__get_user(uc_flags, &frame->uc.uc_flags))
		goto badframe;

	set_current_blocked(&set);

	if (restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
		goto badframe;

	if (restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->ax;

badframe:
	signal_fault(regs, frame, "rt_sigreturn");
	return 0;
}
