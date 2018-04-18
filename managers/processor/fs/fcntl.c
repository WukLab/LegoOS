/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/stat.h>
#include <lego/slab.h>
#include <lego/uaccess.h>
#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <processor/processor.h>
#include <processor/fs.h>

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)

static int setfl(struct file * filp, unsigned long arg)
{
	/*
	 * O_APPEND cannot be cleared
	 */
	if (((arg ^ filp->f_flags) & O_APPEND))
		return -EPERM;

	/* does not allow set O_DIRECT */
	if (arg & O_DIRECT)
		return -EINVAL;

	spin_lock(&filp->f_pos_lock);
	filp->f_flags = (arg & SETFL_MASK) | (filp->f_flags & ~SETFL_MASK);
	spin_unlock(&filp->f_pos_lock);

	return 0;
}

static long do_fcntl(int fd, unsigned int cmd, unsigned long arg, struct file *fp)
{
	long err = -EINVAL;

	switch(cmd) {
	case F_GETFD:
		err = get_close_on_exec(fd) ? FD_CLOEXEC : 0;
		break;
	case F_SETFD:
		err = 0;
		set_close_on_exec(fd, arg & FD_CLOEXEC);
		break;
	case F_GETFL:
		err = fp->f_flags;
		break;
	case F_SETFL:
		err = setfl(fp, arg);
		break;
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_GETOWN:
	case F_SETOWN:
	case F_GETOWN_EX:
	case F_SETOWN_EX:
	case F_GETOWNER_UIDS:
	case F_GETSIG:
	case F_SETSIG:
	case F_GETLEASE:
	case F_SETLEASE:
	case F_NOTIFY:
	case F_SETPIPE_SZ:
	case F_GETPIPE_SZ:
		WARN(1, "Cmd not implemented: %u\n", cmd);
		err = 0;
		break;
	default:
		break;
	}
	return err;
}

SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	long err;
	struct file *fp;

	fp = fdget(fd);
	if (!fp)
		return -EBADF;

	err = do_fcntl(fd, cmd, arg, fp);

	put_file(fp);
	return err;
}
