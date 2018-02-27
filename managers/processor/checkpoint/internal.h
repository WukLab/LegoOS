/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _CHECKPOINT_INTERNAL_H_
#define _CHECKPOINT_INTERNAL_H_

#ifdef CONFIG_DEBUG_CHECKPOINT
#define chk_debug(fmt,...)	\
	pr_debug("%s(): "fmt "\n", __func__, __VA_ARGS__)
#else
static inline void chk_debug(const char *fmt, ...) { }
#endif

/* Save */
int save_open_files(struct task_struct *, struct process_snapshot *);
int save_signals(struct task_struct *, struct process_snapshot *);

void save_thread_regs(struct task_struct *, struct ss_task_struct *);

void revert_save_open_files(struct task_struct *, struct process_snapshot *);

/* Restore */

#endif /* _CHECKPOINT_INTERNAL_H_ */
