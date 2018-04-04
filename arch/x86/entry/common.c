/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>
#include <lego/strace.h>
#include <lego/syscalls.h>
#include <processor/processor.h>
#include <generated/asm-offsets.h>

/*
 * Low-level thread flags we need to check before return to user-mode.
 * Each flag represents a pending job. Flags may be re-set during the
 * handling of the jobs:
 */
#define EXIT_TO_USERMODE_LOOP_FLAGS \
	(_TIF_SIGPENDING | _TIF_NEED_RESCHED | _TIF_NEED_CHECKPOINT)

static void exit_to_usermode_loop(struct pt_regs *regs, u32 cached_flags)
{
	/*
	 * In order to return to user mode, we need to have IRQs off with
	 * none of _TIF_SIGPENDING, _TIF_NOTIFY_RESUME, _TIF_USER_RETURN_NOTIFY,
	 * _TIF_UPROBE, or _TIF_NEED_RESCHED set.  Several of these flags
	 * can be set at any time on preemptable kernels if we have IRQs on,
	 * so we need to loop.  Disabling preemption wouldn't help: doing the
	 * work to clear some of the flags can sleep.
	 */
	while (true) {
		/* We have work to do. */
		local_irq_enable();

#ifdef CONFIG_CHECKPOINT
		if (cached_flags & _TIF_NEED_CHECKPOINT)
			checkpoint_thread(current);
#endif

		if (cached_flags & _TIF_NEED_RESCHED)
			schedule();

		/* deal with pending signal delivery */
		if (cached_flags & _TIF_SIGPENDING)
			do_signal(regs);

		/* Disable IRQs and retry */
		local_irq_disable();

		cached_flags = READ_ONCE(current_thread_info()->flags);

		if (!(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
			break;
	}
}

/* Called with IRQs disabled. */
__visible inline void prepare_exit_to_usermode(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags;

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();

	cached_flags = READ_ONCE(ti->flags);

	if (unlikely(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
		exit_to_usermode_loop(regs, cached_flags);

#ifdef CONFIG_COMPAT
	/*
	 * Compat syscalls set TS_COMPAT.  Make sure we clear it before
	 * returning to user mode.  We need to clear it *after* signal
	 * handling, because syscall restart has a fixup for compat
	 * syscalls.  The fixup is exercised by the ptrace_syscall_32
	 * selftest.
	 *
	 * We also need to clear TS_REGS_POKED_I386: the 32-bit tracer
	 * special case only applies after poking regs and before the
	 * very next return to user mode.
	 */
	current->thread.status &= ~(TS_COMPAT|TS_I386_REGS_POKED);
#endif
}

/*
 * Called with IRQs on and fully valid regs.  Returns with IRQs off in a
 * state such that we can immediately switch to user mode.
 */
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
	if (WARN(irqs_disabled(), "syscall %ld left IRQs disabled", regs->orig_ax))
		local_irq_enable();

	local_irq_disable();
	prepare_exit_to_usermode(regs);
}

#ifdef CONFIG_X86_64
__visible void do_syscall_64(struct pt_regs *regs)
{
	unsigned long nr = regs->orig_ax;

	local_irq_enable();

	/*
	 * NB: Native and x32 syscalls are dispatched from the same
	 * table.  The only functional difference is the x32 bit in
	 * regs->orig_ax, which changes the behavior of some syscalls.
	 */
	strace_syscall_enter(regs);
	if (likely(nr < NR_syscalls)) {
		regs->ax = sys_call_table[nr](
			regs->di, regs->si, regs->dx,
			regs->r10, regs->r8, regs->r9);
	}
	strace_syscall_exit(regs);

	syscall_return_slowpath(regs);
}
#endif

/*
 * Legacy Stuff
 * Lego really does not support these at this stage.
 */

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
/*
 * Does a 32-bit syscall.  Called with IRQs on in CONTEXT_KERNEL.  Does
 * all entry and exit work and returns with IRQs off.  This function is
 * extremely hot in workloads that use it, and it's usually called from
 * do_fast_syscall_32, so forcibly inline it to improve performance.
 */
static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs)
{
#ifdef CONFIG_IA32_EMULATION
	current->thread.status |= TS_COMPAT;
#endif

	BUG();
}

/* Handles int $0x80 */
__visible void do_int80_syscall_32(struct pt_regs *regs)
{
	BUG();
}

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible long do_fast_syscall_32(struct pt_regs *regs)
{
	BUG();
}
#endif
