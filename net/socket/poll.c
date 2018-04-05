/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file implements the poll system call
 */

#include <lego/syscalls.h>
#include <lego/socket.h>
#include <lego/atomic.h>
#include <processor/processor.h>
#include <lego/net.h>
#include <lego/fit_ibapi.h>
#include <lego/files.h>
#include <processor/fs.h>
#include <lego/spinlock.h>
#include <lego/hashtable.h>
#include <lego/comp_storage.h>
#include <lego/delay.h>
#include <lego/time.h>
#include <lego/timer.h>
#include <lego/jiffies.h>

#ifdef CONFIG_DEBUG_POLL
#define poll_debug(fmt, ...) \
	pr_debug("%s():%d " fmt, __func__, __LINE__, __VA_ARGS__)
#else
static inline void poll_debug(const char *fmt, ...) { }
#endif

struct poll_struct {
	wait_queue_head_t wq;
	struct list_head file_list;
};

static int poll_insert(struct poll_struct *ps, int fd, short events, short *urevent)
{
	int error = 0, revents, pwake = 0;
	unsigned long flags;
	struct file *file;

	/* 
	 * according to poll syscall description, if fd is neagative,
	 * it will be ignored and the revents field returns zero.
	 */
	if (fd < 0)
		return 0;

	file = fdget(fd);
	if (!file)
		return -ENFILE;

	poll_debug("%s: ps %p fd %d file %p\n", __func__, ps, fd, file);

	/* Add the current item to the list of active epoll hook for this file */
	/* XXX add lock back if seeing multithreaded poll */
	//spin_lock(&tfile->f_lock);
	list_add_tail(&ps->file_list, &file->f_poll_links);
	//spin_unlock(&tfile->f_lock);

	/* If the file is already "ready" we drop it inside the ready list */
	revents = file->ready_state;
	if (revents & events) {
		*urevent = revents & events;
		return 1;
	}

	return 0;
}

static int files_events_available(struct pollfd *poll_fds, int nfds)
{
	struct file *file;
	int i, res = 0;

	for (i = 0; i < nfds; i++) {
		file = fdget(poll_fds[i].fd);
		if (!file)
			return -ENFILE;
		if (file->ready_state & poll_fds[i].events) {
			res = 1;
		}
	}

	return res;
}

static int poll_send_events(struct pollfd *poll_fds, int nfds)
{
	int i;
	struct file *file;
	int cnt = 0;

	poll_debug("%s\n", __func__);

	for (i = 0; i < nfds; i++) {
		file = fdget(poll_fds[i].fd);
		if (!file)
			return -ENFILE;
		poll_fds[i].revents |= (poll_fds[i].events & file->ready_state);
		if (poll_fds[i].events & file->ready_state)
			cnt++;
	}

	return cnt;
}

int lego_poll_callback(struct file *f)
{
	struct poll_struct *entry;

	list_for_each_entry(entry, &f->f_poll_links, file_list) {
		poll_debug("%s entry %p file %p\n", __func__, entry, f);
		wake_up_locked(&entry->wq);
	}

	return 0;
}

static int poll_wait(struct poll_struct *ps, struct pollfd *poll_fds, int nfds, long jtimeout)
{
	int res = 0, eavail, timed_out = 0;
	unsigned long flags;
	long slack = 0;
	wait_queue_t wait;

	if (jtimeout == 0) {
		/*
		 * Avoid the unnecessary trip to the wait queue loop, if the
		 * caller specified a non blocking operation.
		 */
		timed_out = 1;
		goto check_events;
	}

	poll_debug("%s: nfds %d timeout %d\n", __func__, nfds, jtimeout);

fetch_events:
	/* TODO: do we need any lock here? */
	if (!(files_events_available(poll_fds, nfds))) {
		poll_debug("%s event unavailable now\n", __func__);
		/*
		 * We don't have any available event to return to the caller.
		 * We need to sleep here, and we will be wake up by
		 * poll_callback() when events will become available.
		 */
		init_waitqueue_entry(&wait, current);
		__add_wait_queue_exclusive(&ps->wq, &wait);

		for (;;) {
			/*
			 * We don't want to sleep if the poll_callback() sends us
			 * a wakeup in between. That's why we set the task state
			 * to TASK_INTERRUPTIBLE before doing the checks.
			 */
			set_current_state(TASK_INTERRUPTIBLE);
			if (files_events_available(poll_fds, nfds) || timed_out)
				break;
			if (signal_pending(current)) {
				res = -EINTR;
				break;
			}

			jtimeout = schedule_timeout(jtimeout);
		}
		__remove_wait_queue(&ps->wq, &wait);

		set_current_state(TASK_RUNNING);
	}
check_events:
	/* Is it worth to try to dig for events ? */
	eavail = files_events_available(poll_fds, nfds);

	/*
	 * Try to transfer events to user space. In case we get 0 events and
	 * there's still timeout left over, we go trying again in search of
	 * more luck.
	 */
	if (!res && eavail &&
	    !(res = poll_send_events(poll_fds, nfds)) && !timed_out)
		goto fetch_events;

	return res;
}

/*
 * The poll system call implementation
 * On success, return the number of files that have nonzero revents fields.
 * A return value of 0 indicates that the call timed out and no file descriptors were ready.
 * On error, -1 is returned.
 */
asmlinkage long sys_poll(struct pollfd __user *ufds, unsigned int nfds,
			long timeout_msecs)
{
	s64 timeout_jiffies;
	int i, ret, result = 0;
	struct list_head poll_list;
	short revent;
	struct pollfd *poll_fds;
	struct poll_struct *ps;

	if (timeout_msecs > 0) {
#if HZ > 1000
		/* We can only overflow if HZ > 1000 */
		if (timeout_msecs / 1000 > (s64)0x7fffffffffffffffULL / (s64)HZ)
			timeout_jiffies = -1;
		else
#endif
			timeout_jiffies = msecs_to_jiffies(timeout_msecs);
	} else {
		/* Infinite (< 0) or no (0) timeout */
		timeout_jiffies = timeout_msecs;
	}

	poll_fds = (struct pollfd *)kmalloc(sizeof(struct pollfd) * nfds, GFP_KERNEL);

	copy_from_user(poll_fds, ufds, sizeof(struct pollfd) * nfds);

	ps = (struct poll_struct *)kmalloc(sizeof(struct poll_struct), GFP_KERNEL);
	BUG_ON(!ps);
	init_waitqueue_head(&ps->wq);

	for (i = 0; i < nfds; i++) {
		ret = poll_insert(ps, poll_fds[i].fd, poll_fds[i].events, &revent);
		if (ret == 1) {
			copy_to_user(&poll_fds[i].revents, &revent, sizeof(short));
			result++;
		}
		if (ret < 0)
			return -1;
	}

	if (result == 0) {
		result = poll_wait(ps, poll_fds, nfds, timeout_jiffies);
	}

	return result;
}

