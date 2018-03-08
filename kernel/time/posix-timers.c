/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * TODO: POSIX clock and timers
 */

#include <lego/sched.h>
#include <lego/signal.h>

/*
 * This function is exported for use by the signal deliver code.  It is
 * called just prior to the info block being released and passes that
 * block to us.  It's function is to update the overrun entry AND to
 * restart the timer.  It should only be called if the timer is to be
 * restarted (i.e. we have flagged this in the sys_private entry of the
 * info block).
 *
 * To protect against the timer going away while the interrupt is queued,
 * we require that the it_requeue_pending flag be set.
 */
void do_schedule_next_timer(struct siginfo *info)
{
}

/*
 * This is called by do_exit or de_thread, only when there are no more
 * references to the shared signal_struct.
 */
void exit_itimers(struct signal_struct *sig)
{
}

/* TODO */
void posix_cpu_timers_exit(struct task_struct *task)
{

}

void posix_cpu_timers_exit_group(struct task_struct *task)
{

}
