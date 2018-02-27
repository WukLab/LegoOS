/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SIGNALFD_H_
#define _LEGO_SIGNALFD_H_

#include <lego/signal.h>

/*
 * TODO: signalfd SYSCALL
 */

#ifdef CONFIG_SIGNALFD
/*
 * Deliver the signal to listening signalfd.
 */
static inline void signalfd_notify(struct task_struct *tsk, int sig)
{
	BUG();
}
void signalfd_cleanup(struct sighand_struct *sighand);
#else
static inline void signalfd_notify(struct task_struct *tsk, int sig) { }
static inline void signalfd_cleanup(struct sighand_struct *sighand) { }
#endif

#endif /* _LEGO_SIGNALFD_H_ */
