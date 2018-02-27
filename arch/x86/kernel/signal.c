/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <asm/fpu/signal.h>
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

#ifdef CONFIG_X86_32
		set_user_gs(regs, GET_SEG(gs));
		COPY_SEG(fs);
		COPY_SEG(es);
		COPY_SEG(ds);
#endif /* CONFIG_X86_32 */

		COPY(di); COPY(si); COPY(bp); COPY(sp); COPY(bx);
		COPY(dx); COPY(cx); COPY(ip); COPY(ax);

#ifdef CONFIG_X86_64
		COPY(r8);
		COPY(r9);
		COPY(r10);
		COPY(r11);
		COPY(r12);
		COPY(r13);
		COPY(r14);
		COPY(r15);
#endif /* CONFIG_X86_64 */

		COPY_SEG_CPL3(cs);
		COPY_SEG_CPL3(ss);

#ifdef CONFIG_X86_64
		/*
		 * Fix up SS if needed for the benefit of old DOSEMU and
		 * CRIU.
		 */
		if (unlikely(!(uc_flags & UC_STRICT_RESTORE_SS) &&
			     user_64bit_mode(regs)))
			force_valid_ss(regs);
#endif

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

#ifdef CONFIG_X86_32
		put_user_ex(get_user_gs(regs), (unsigned int __user *)&sc->gs);
		put_user_ex(regs->fs, (unsigned int __user *)&sc->fs);
		put_user_ex(regs->es, (unsigned int __user *)&sc->es);
		put_user_ex(regs->ds, (unsigned int __user *)&sc->ds);
#endif /* CONFIG_X86_32 */

		put_user_ex(regs->di, &sc->di);
		put_user_ex(regs->si, &sc->si);
		put_user_ex(regs->bp, &sc->bp);
		put_user_ex(regs->sp, &sc->sp);
		put_user_ex(regs->bx, &sc->bx);
		put_user_ex(regs->dx, &sc->dx);
		put_user_ex(regs->cx, &sc->cx);
		put_user_ex(regs->ax, &sc->ax);
#ifdef CONFIG_X86_64
		put_user_ex(regs->r8, &sc->r8);
		put_user_ex(regs->r9, &sc->r9);
		put_user_ex(regs->r10, &sc->r10);
		put_user_ex(regs->r11, &sc->r11);
		put_user_ex(regs->r12, &sc->r12);
		put_user_ex(regs->r13, &sc->r13);
		put_user_ex(regs->r14, &sc->r14);
		put_user_ex(regs->r15, &sc->r15);
#endif /* CONFIG_X86_64 */

		put_user_ex(current->thread.trap_nr, &sc->trapno);
		put_user_ex(current->thread.error_code, &sc->err);
		put_user_ex(regs->ip, &sc->ip);
#ifdef CONFIG_X86_32
		put_user_ex(regs->cs, (unsigned int __user *)&sc->cs);
		put_user_ex(regs->flags, &sc->flags);
		put_user_ex(regs->sp, &sc->sp_at_signal);
		put_user_ex(regs->ss, (unsigned int __user *)&sc->ss);
#else /* !CONFIG_X86_32 */
		put_user_ex(regs->flags, &sc->flags);
		put_user_ex(regs->cs, &sc->cs);
		put_user_ex(0, &sc->gs);
		put_user_ex(0, &sc->fs);
		put_user_ex(regs->ss, &sc->ss);
#endif /* CONFIG_X86_32 */

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

/*
 * Determine which stack to use..
 */
static unsigned long align_sigframe(unsigned long sp)
{
#ifdef CONFIG_X86_32
	/*
	 * Align the stack pointer according to the i386 ABI,
	 * i.e. so that on function entry ((sp + 4) & 15) == 0.
	 */
	sp = ((sp + 4) & -16ul) - 4;
#else /* !CONFIG_X86_32 */
	sp = round_down(sp, 16) - 8;
#endif
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
	if (IS_ENABLED(CONFIG_X86_64))
		sp -= 128;

	/* This is the X/Open sanctioned signal stack switching.  */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (sas_ss_flags(sp) == 0)
			sp = current->sas_ss_sp + current->sas_ss_size;
	} else if (IS_ENABLED(CONFIG_X86_32) &&
		   !onsigstack &&
		   (regs->ss & 0xffff) != __USER_DS &&
		   !(ka->sa.sa_flags & SA_RESTORER) &&
		   ka->sa.sa_restorer) {
		/* This is the legacy signal stack switching. */
		sp = (unsigned long) ka->sa.sa_restorer;
		BUG();
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

static inline int is_ia32_compat_frame(struct ksignal *ksig)
{
	return IS_ENABLED(CONFIG_IA32_EMULATION) &&
		ksig->ka.sa.sa_flags & SA_IA32_ABI;
}

static inline int is_ia32_frame(struct ksignal *ksig)
{
	return IS_ENABLED(CONFIG_X86_32) || is_ia32_compat_frame(ksig);
}

static inline int is_x32_frame(struct ksignal *ksig)
{
	return IS_ENABLED(CONFIG_X86_X32_ABI) &&
		ksig->ka.sa.sa_flags & SA_X32_ABI;
}

static int
setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
{
	sigset_t *set = sigmask_to_save();

	/* Set up the stack frame */
	if (is_ia32_frame(ksig)) {
		BUG();
	} else if (is_x32_frame(ksig)) {
		BUG();
	} else {
		return __setup_rt_frame(ksig->sig, ksig, set, regs);
	}
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

static inline unsigned long get_nr_restart_syscall(const struct pt_regs *regs)
{
	/*
	 * This function is fundamentally broken as currently
	 * implemented.
	 *
	 * The idea is that we want to trigger a call to the
	 * restart_block() syscall and that we want in_ia32_syscall(),
	 * in_x32_syscall(), etc. to match whatever they were in the
	 * syscall being restarted.  We assume that the syscall
	 * instruction at (regs->ip - 2) matches whatever syscall
	 * instruction we used to enter in the first place.
	 *
	 * The problem is that we can get here when ptrace pokes
	 * syscall-like values into regs even if we're not in a syscall
	 * at all.
	 *
	 * For now, we maintain historical behavior and guess based on
	 * stored state.  We could do better by saving the actual
	 * syscall arch in restart_block or (with caveats on x32) by
	 * checking if regs->ip points to 'int $0x80'.  The current
	 * behavior is incorrect if a tracer has a different bitness
	 * than the tracee.
	 */
#ifdef CONFIG_IA32_EMULATION
	if (current->thread.status & (TS_COMPAT|TS_I386_REGS_POKED)) {
		BUG();
	}
#endif
	return __NR_restart_syscall;
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
		/*
		 * Got a signal which has user-registered handler
		 * (Other signals are already handled by get_signal()):
		 */
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
			regs->ax = get_nr_restart_syscall(regs);
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

	__syscall_enter();

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
