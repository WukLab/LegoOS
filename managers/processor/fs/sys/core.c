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
#include <processor/fs.h>
#include <processor/processor.h>

extern struct file_operations sys_devices_system_cpu_online_ops;

struct sys_file_struct {
	char f_name[FILENAME_LEN_DEFAULT];
	const struct file_operations *f_op;
};

static struct sys_file_struct sys_files[] = {
	{
		.f_name	= "/sys/devices/system/cpu/online",
		.f_op	=  &sys_devices_system_cpu_online_ops,
	},
};

int sys_file_open(struct file *f, char *f_name)
{
	struct sys_file_struct *sys_file;
	int i, ret;

	ret = -EBADF;
	for (i = 0; i < ARRAY_SIZE(sys_files); i++) {
		sys_file = &sys_files[i];
		if (f_name_equal(f_name, sys_file->f_name)) {
			f->f_op = sys_file->f_op;
			ret = 0;
			break;
		}
	}

	return ret;
}
