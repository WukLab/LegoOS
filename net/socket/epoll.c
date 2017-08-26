/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file implements all epoll syscalls:
 * 	epoll_create
 * 	epoll_wait
 * 	epoll_ctl
 * and epoll file ops
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

static ssize_t sock_ep_read(struct file *f, char __user *ubuf, size_t len, loff_t *offset)
{
}

static ssize_t sock_ep_write(struct file *f, const char __user *ubuf, size_t len, loff_t *offset)
{
}

/* File callbacks that implement the eventpoll file behaviour */
static const struct file_operations eventpoll_fops = {
	.read		= sock_ep_read,
	.write		= sock_ep_write,
};

static inline int is_file_epoll(struct file *f)
{
	return f->f_op == &eventpoll_fops;
}

/*
 * Open an eventpoll file descriptor.
 */
SYSCALL_DEFINE1(epoll_create1, int, flags)
{
	int error, fd = -1;

	/*
	 * Create the internal data structure ("struct eventpoll").
	 */
	error = ep_alloc(&ep);
	if (error < 0)
		return error;
	/*
	 * Creates all the items needed to setup an eventpoll file. That is,
	 * a file structure and a free file descriptor.
	 */
	fd = sys_open("epoll", O_RDWR | O_CREAT, 0);
	if (fd < 0) {
		error = fd;
		return error;
	}
	fd->f_op = eventpoll_fops;
	return fd;
}

SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

	return sys_epoll_create1(0);
}

/* Tells if the epoll_ctl(2) operation needs an event copy from userspace */
static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}

/*
 * The following function implements the controller interface for
 * the eventpoll file that enables the insertion/removal/change of
 * file descriptors inside the interest set.
 */
SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	int error;
	int did_lock_epmutex = 0;
	struct file *file, *tfile;
	struct lego_eventpoll *ep;
	struct epitem *epi;
	struct epoll_event epds;

	error = -EFAULT;
	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		goto error_return;

	/* Get the "struct file *" for the eventpoll file */
	error = -EBADF;
	file = fdget(epfd);
	if (!file)
		goto error_return;

	/* Get the "struct file *" for the target file */
	tfile = fget(fd);
	if (!tfile)
		goto error_fput;

// TODO
	/* The target file descriptor must support poll */
//	error = -EPERM;
//	if (!tfile->f_op || !tfile->f_op->poll)
//		goto error_tgt_fput;

	/* Check if EPOLLWAKEUP is allowed */
	if ((epds.events & EPOLLWAKEUP) && !capable(CAP_BLOCK_SUSPEND))
		epds.events &= ~EPOLLWAKEUP;

	/*
	 * We have to check that the file structure underneath the file descriptor
	 * the user passed to us _is_ an eventpoll file. And also we do not permit
	 * adding an epoll file descriptor inside itself.
	 */
	error = -EINVAL;
	if (file == tfile || !is_file_epoll(file))
		goto error_tgt_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = (struct lego_eventpoll *)file->private_data;

	/*
	 * When we insert an epoll file descriptor, inside another epoll file
	 * descriptor, there is the change of creating closed loops, which are
	 * better be handled here, than in more critical paths. While we are
	 * checking for loops we also determine the list of files reachable
	 * and hang them on the tfile_check_list, so we can check that we
	 * haven't created too many possible wakeup paths.
	 *
	 * We need to hold the epmutex across both ep_insert and ep_remove
	 * b/c we want to make sure we are looking at a coherent view of
	 * epoll network.
	 */
	if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_DEL) {
		mutex_lock(&epmutex);
		did_lock_epmutex = 1;
	}
	if (op == EPOLL_CTL_ADD) {
		list_add(&tfile->f_tfile_llink, &tfile_check_list);
	}

	mutex_lock_nested(&ep->mtx, 0);

	/*
	 * Try to lookup the file inside our RB tree, Since we grabbed "mtx"
	 * above, we can be sure to be able to use the item looked up by
	 * ep_find() till we release the mutex.
	 */
	epi = ep_find(ep, tfile, fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= POLLERR | POLLHUP;
			error = ep_insert(ep, &epds, tfile, fd);
		} else
			error = -EEXIST;
		clear_tfile_check_list();
		break;
	case EPOLL_CTL_DEL:
		if (epi)
			error = ep_remove(ep, epi);
		else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			epds.events |= POLLERR | POLLHUP;
			error = ep_modify(ep, epi, &epds);
		} else
			error = -ENOENT;
		break;
	}
	mutex_unlock(&ep->mtx);

error_tgt_fput:
	if (did_lock_epmutex)
		mutex_unlock(&epmutex);

	fput(tfile);
error_fput:
	fput(file);
error_return:

	return error;
}

/*
 * Implement the event wait interface for the eventpoll file. It is the kernel
 * part of the user space epoll_wait(2).
 */
SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout)
{
	int error;
	struct file *f;
	struct eventpoll *ep;

	/* The maximum number of event must be greater than zero */
	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
		return -EINVAL;

	/* Get the "struct file *" for the eventpoll file */
	f = fdget(epfd);
	if (!f)
		return -EBADF;

	/*
	 * We have to check that the file structure underneath the fd
	 * the user passed to us _is_ an eventpoll file.
	 */
	error = -EINVAL;
	if (!is_file_epoll(f))
		goto error_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = f.file->private_data;

	/* Time to fish for events ... */
	error = ep_poll(ep, events, maxevents, timeout);

error_fput:
	fdput(f);
	return error;
}

/*
 * POSIX select on fd_sets
 * Only supporting inp now (incoming buffer)
 */
SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
		fd_set __user *, exp, struct timeval __user *, tvp)
{
#if 0
	int fd;
	struct timeval *start, *end;
	struct timeval *timeout;
	struct lego_socket *sock;
	struct file *f = fdget(fd);

	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;

	copy_from_user(timeout, tvp, sizeof (struct timeval));
//	gettimeofday(

	while (1) {
		fd = inp;
		if ((sock->avail_buf_size) > 0) {
		}
	}	
#endif
}


