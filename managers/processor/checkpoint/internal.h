/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _CHECKPOINT_INTERNAL_H_
#define _CHECKPOINT_INTERNAL_H_

#undef debug
#define debug(fmt,...) pr_info(fmt, ##__VA_ARGS__)

/* Save */
int save_open_files(struct task_struct *, struct process_snapshot *);
int save_signals(struct task_struct *, struct process_snapshot *);

void save_thread_regs(struct task_struct *, struct ss_task_struct *);

void revert_save_open_files(struct task_struct *, struct process_snapshot *);

/* Restore */

#endif /* _CHECKPOINT_INTERNAL_H_ */
