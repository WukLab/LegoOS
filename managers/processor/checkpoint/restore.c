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

static LIST_HEAD(restorer_work_list);
static DEFINE_SPINLOCK(restorer_work_lock);
static struct task_struct *restorer_worker;

struct restorer_work_info {
	/* Info passed to restorer from restore_process_snapshot() */
	struct process_snapshot	*pss;

	/* Results passed back to restore_process_snapshot() from restorer */
	struct task_struct	*result;
	struct completion	*done;

	struct list_head	list;
};

static int restorer(void *_info)
{
	struct restorer_work_info *info = _info;
	struct process_snapshot *pss = info->pss;

	dump_process_snapshot(pss, "Restorer");

	/*
	 * Pass the info back to our caller
	 * and wake it:
	 */
	info->result = current;
	complete(info->done);

	for(;;);
	return 0;
}

static void create_restorer(struct restorer_work_info *info)
{
	int pid;

	pid = kernel_thread(restorer, info, 0);
	if (pid < 0) {
		WARN_ON_ONCE(1);
		info->result = ERR_PTR(pid);
		complete(info->done);
	}
}

/*
 * It dequeue work from work_list, and creates a restorer to construct
 * a new process from snapshot. Any error is reported by restorer in
 * the info->result field.
 */
int restorer_worker_thread(void *unused)
{
	set_cpus_allowed_ptr(current, cpu_possible_mask);

	for (;;) {
		/* Sleep until someone wakes me up before september ends */
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

			/*
			 * Release the lock so others can attach work.
			 * The real work may take some time.
			 */
			spin_unlock(&restorer_work_lock);

			create_restorer(info);

			spin_lock(&restorer_work_lock);
		}
		spin_unlock(&restorer_work_lock);
	}

	return 0;
}

/**
 * restore_process_snapshot	-	Restore a process from snapshot
 * @pss: the snapshot
 *
 * This function is synchronized. It will wait until the new process
 * is live from the snapshot. The real work of restoring is done by
 * restorer thread.
 *
 * Return the task_struct of the new process.
 * On failure, ERR_PTR is returned.
 */
struct task_struct *restore_process_snapshot(struct process_snapshot *pss)
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

	wake_up_process(restorer_worker);
	wait_for_completion(&done);

	return info.result;
}

void __init checkpoint_init(void)
{
	restorer_worker = kthread_run(restorer_worker_thread, NULL, "restorer");
	if (IS_ERR(restorer_worker))
		panic("Fail to create checkpointing restore thread!");
}
