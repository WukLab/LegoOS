/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pid.h>
#include <lego/timer.h>
#include <lego/ktime.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/spinlock.h>
#include <lego/completion.h>
#include <lego/checkpoint.h>

#include "internal.h"

static DEFINE_SPINLOCK(restorer_work_lock);
static LIST_HEAD(restorer_work_list);
static struct task_struct *restorer_task;

struct restorer_work_info {
	struct process_snapshot	*pss;
	struct completion	*done;
	struct list_head	list;
};

/*
 * Do the real work of restoring a process from its snapshot.
 * Called from restorer daemon thread.
 */
static void restore_process_snapshot(struct restorer_work_info *info)
{
	struct process_snapshot *pss = info->pss;

	dump_process_snapshot(pss);
}

int restore_thread_fn(void *unused)
{
	set_cpus_allowed_ptr(current, cpu_possible_mask);

	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&restorer_work_list))
			schedule();
		__set_current_state(TASK_RUNNING);

		spin_lock(&restorer_work_lock);
		while (!list_empty(&restorer_work_list)) {
			struct restorer_work_info *info;

			info = list_entry(restorer_work_list.next,
					struct restorer_work_info, list);
			list_del_init(&info->list);

			/* Release the lock so others can attach work */
			spin_unlock(&restorer_work_lock);

			restore_process_snapshot(info);

			/* Obtatin lock again */
			spin_lock(&restorer_work_lock);
		}
		spin_unlock(&restorer_work_lock);
	}

	return 0;
}

/**
 * restore_process	-	Restore a process from snapshot
 * @pss: the snapshot
 *
 * This function is synchronized. It will wait until the new process
 * is live from the snapshot. The real work of restoring is done by
 * restorer daemon thread.
 */
int restore_process(struct process_snapshot *pss)
{
	DEFINE_COMPLETION(done);
	struct restorer_work_info info;

	/*
	 * Note:
	 * If we decide to make this function a-sync later,
	 * we need to allocate info instead of using stack.
	 */
	info.pss = pss;
	info.done = &done;

	spin_lock(&restorer_work_lock);
	list_add_tail(&info.list, &restorer_work_list);
	spin_unlock(&restorer_work_lock);

	/*
	 * Wake up restorer and wait for its completion...
	 */
	wake_up_process(restorer_task);
	wait_for_completion(&done);

	return 0;
}

void __init checkpoint_init(void)
{
	restorer_task = kthread_run(restore_thread_fn, NULL, "restorer");
	if (IS_ERR(restorer_task))
		panic("Fail to create checkpointing restore thread!");
}
