/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/atomic.h>
#include <lego/kernel_stat.h>

#include "sched.h"

DEFINE_PER_CPU(struct kernel_cpustat, kernel_cpustat);

static inline void task_group_account_field(struct task_struct *p, int index,
					    u64 tmp)
{
	__this_cpu_add(kernel_cpustat.cpustat[index], tmp);
}

/*
 * Account for idle time.
 * @cputime: the cpu time spent in idle wait
 */
void account_idle_time(cputime_t cputime)
{
	u64 *cpustat = kcpustat_this_cpu->cpustat;
	struct rq *rq = this_rq();

	if (atomic_read(&rq->nr_iowait) > 0)
		cpustat[CPUTIME_IOWAIT] += (u64) cputime;
	else
		cpustat[CPUTIME_IDLE] += (u64) cputime;
}

/*
 * Account system cpu time to a process and desired cpustat field
 * @p: the process that the cpu time gets accounted to
 * @cputime: the cpu time spent in kernel space since the last update
 * @cputime_scaled: cputime scaled by cpu frequency
 * @target_cputime64: pointer to cpustat field that has to be updated
 */
static inline
void __account_system_time(struct task_struct *p, cputime_t cputime,
			cputime_t cputime_scaled, int index)
{
	/* Add system time to process. */
	p->stime += cputime;
	p->stimescaled += cputime_scaled;

	/* Add system time to cpustat. */
	task_group_account_field(p, index, (u64) cputime);
}

/*
 * Account system cpu time to a process.
 * @p: the process that the cpu time gets accounted to
 * @cputime: the cpu time spent in kernel space since the last update
 * @cputime_scaled: cputime scaled by cpu frequency
 */
void account_system_time(struct task_struct *p,
			 cputime_t cputime, cputime_t cputime_scaled)
{
	int index = CPUTIME_SYSTEM;
	__account_system_time(p, cputime, cputime_scaled, index);
}

/*
 * Account user cpu time to a process.
 * @p: the process that the cpu time gets accounted to
 * @cputime: the cpu time spent in user space since the last update
 * @cputime_scaled: cputime scaled by cpu frequency
 */
void account_user_time(struct task_struct *p, cputime_t cputime,
		       cputime_t cputime_scaled)
{
	int index;

	/* Add user time to process. */
	p->utime += cputime;
	p->utimescaled += cputime_scaled;

	index = (task_nice(p) > 0) ? CPUTIME_NICE : CPUTIME_USER;

	/* Add user time to cpustat. */
	task_group_account_field(p, index, (u64) cputime);
}

/*
 * Account a single tick of cpu time.
 * @p: the process that the cpu time gets accounted to
 * @user_tick: indicates if the tick is a user or a system tick
 */
void account_process_tick(struct task_struct *p, int user_tick)
{
	cputime_t cputime, scaled;
	struct rq *rq = this_rq();

	cputime = cputime_one_jiffy;
	scaled = cputime_to_scaled(cputime);

	if (user_tick)
		account_user_time(p, cputime, scaled);
	else if (p != rq->idle)
		account_system_time(p, cputime, scaled);
	else
		account_idle_time(cputime);
}
