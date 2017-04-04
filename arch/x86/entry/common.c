/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>

static inline void do_signal(struct pt_regs *regs)
{

}

#define EXIT_TO_USERMODE_LOOP_FLAGS				\
	(_TIF_SIGPENDING | _TIF_NEED_RESCHED)

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
}

/*
 * Called with IRQs on and fully valid regs.  Returns with IRQs off in a
 * state such that we can immediately switch to user mode.
 */
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
	local_irq_disable();
	prepare_exit_to_usermode(regs);
}
