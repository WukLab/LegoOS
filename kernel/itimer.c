/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/jiffies.h>
#include <lego/sched.h>
#include <lego/syscalls.h>
#include <lego/printk.h>

int do_getitimer(int which, struct itimerval *value)
{
	register unsigned long val = 0;
	struct task_struct *tsk = current;

	switch (which) {
	case ITIMER_REAL:
		spin_lock_irq(&tsk->sighand->siglock);
		if (timer_pending(&tsk->signal->real_timer)) {
			val = tsk->signal->real_timer.expires - jiffies;

			if ((long) val <= 0)
				val = 1;
		}
		jiffies_to_timeval(val, &value->it_value);
		jiffies_to_timeval(tsk->signal->it_real_incr, &value->it_interval);
		spin_unlock_irq(&tsk->sighand->siglock);
		break;
	case ITIMER_VIRTUAL:
		pr_warn("ITIMER_VIRTUAL not implemented.\n");
		break;
	case ITIMER_PROF:
		pr_warn("ITIMER_PROF not implemented.\n");
		break;
	default:
		return(-EINVAL);
	}
	return 0;
}

void it_real_fn(unsigned long __data)
{
	struct timer_list * t = (struct timer_list *) __data;
	unsigned long interval;
	struct signal_struct *sig = 
		container_of(t, struct signal_struct, real_timer);

	kill_pid_info(SIGALRM, SEND_SIG_PRIV, sig->leader_pid);
	spin_lock_irq(&sig->curr_target->sighand->siglock);
	interval = sig->it_real_incr;
	if (interval) {
		if (interval > (unsigned long) LONG_MAX)
			interval = LONG_MAX;
		sig->real_timer.expires = jiffies + interval;
		add_timer(&sig->real_timer);
	}
	spin_unlock_irq(&sig->curr_target->sighand->siglock);
}

int do_setitimer(int which, struct itimerval *value, struct itimerval *ovalue)
{
	struct task_struct *tsk = current;
	unsigned long expire;

	if (!timeval_valid(&value->it_value) ||
		!timeval_valid(&value->it_interval))
		return -EINVAL;

	switch (which) {
		case ITIMER_REAL:
again:
			spin_lock_irq(&tsk->sighand->siglock);
			if (ovalue) {
				register unsigned long val = 0;

				if (timer_pending(&tsk->signal->real_timer)) {
					val = tsk->signal->real_timer.expires - jiffies;

				if ((long) val <= 0)
					val = 1;
				}
				jiffies_to_timeval(val, &ovalue->it_value);
				jiffies_to_timeval(tsk->signal->it_real_incr, &ovalue->it_interval);
			}

			/* try to cancel timer */
			if (try_to_del_timer_sync(&tsk->signal->real_timer) < 0) {
				spin_unlock_irq(&tsk->sighand->siglock);
				goto again;
			}
			expire = timeval_to_jiffies(&value->it_value);
			tsk->signal->it_real_incr =
				timeval_to_jiffies(&value->it_interval);
			if (!expire)
				goto unlock;
			if (expire > (unsigned long) LONG_MAX)
				expire = LONG_MAX;
			tsk->signal->real_timer.expires = jiffies + expire;
			/* set call back parameter */
			tsk->signal->real_timer.data = (unsigned long) &tsk->signal->real_timer;
			add_timer(&tsk->signal->real_timer);
unlock:
			spin_unlock_irq(&tsk->sighand->siglock);
			break;
		case ITIMER_VIRTUAL:
			pr_warn("ITIMER_VIRTUAL not implemented.\n");
			break;
		case ITIMER_PROF:
			pr_warn("ITIMER_PROF not implemented.\n");
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value,
		struct itimerval __user *, ovalue)
{
	struct itimerval set_buffer, get_buffer;
	int error;

	if (value) {
		if(copy_from_user(&set_buffer, value, sizeof(set_buffer)))
			return -EFAULT;
	} else {
		memset(&set_buffer, 0, sizeof(set_buffer));
		printk_once(KERN_WARNING "%s calls setitimer() with new_value NULL pointer."
			    " Misfeature support will be removed\n",
			    current->comm);
	}

	error = do_setitimer(which, &set_buffer, ovalue ? &get_buffer : NULL);
	if (error || !ovalue)
		return error;

	if (copy_to_user(ovalue, &get_buffer, sizeof(get_buffer)))
		return -EFAULT;
	return 0;
}
