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

/* 
 * currently, ioctl is faked implementation, currently only tensorflow uses
 * it to set special flag to control tty files. on storage side ioctl need
 * invoking underlying fs ioctl, and do a lot of put_user, get_user,
 * copy_from_user, copy_to_user, which will failed from kernel space
 * we fake ioctl by return:
 * 0 on tty files, -EINVAL on proc/dev/sys/ files, -ENOTTY on regualr files
 */
SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	struct file *filp;
	long ret = 0;

	syscall_enter("fd: %u, cmd: %u, arg: %lu\n", fd, cmd, arg);

	/* std files */
	if (fd <= 2) {
		goto out;
	}

	filp = fdget(fd);
	if (unlikely(!filp)) {
		ret = -EBADF;
		goto out;
	}

	ret = -ENOTTY;
	if (proc_file(filp->f_name) || sys_file(filp->f_name)
			|| dev_file(filp->f_name))
		ret = -EINVAL;

	put_file(filp);

out:
	syscall_exit(ret);
	return ret;
}
