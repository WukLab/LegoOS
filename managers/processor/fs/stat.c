/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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
#include <lego/comp_processor.h>

SYSCALL_DEFINE2(newstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	char buf[FILENAME_LEN_DEFAULT];
	long ret;

	ret = strncpy_from_user(buf, filename, FILENAME_LEN_DEFAULT);
	if (ret < 0)
		return ret;
	debug_syscall_print();
	pr_info("%s(): filename: %s\n", __func__, buf);

	ret = __clear_user(statbuf, sizeof(*statbuf));
	return 0;
}

SYSCALL_DEFINE2(newlstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	char buf[FILENAME_LEN_DEFAULT];
	long ret;

	ret = strncpy_from_user(buf, filename, FILENAME_LEN_DEFAULT);
	if (ret < 0)
		return ret;
	debug_syscall_print();
	pr_info("%s(): filename: %s\n", __func__, buf);

	ret = __clear_user(statbuf, sizeof(*statbuf));
	return 0;
}

SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	debug_syscall_print();
	return -ENOENT;
}
