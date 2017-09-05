/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _PROCESSOR_INCLUDE_FS_H_
#define _PROCESSOR_INCLUDE_FS_H_

#include <lego/bug.h>
#include <lego/files.h>
#include <lego/atomic.h>
#include <lego/string.h>

struct file *fdget(int fd);

void free_fd(struct files_struct *files, int fd);
int alloc_fd(struct files_struct *files, char *filename);

static inline int f_name_equal(char *f_name1, char *f_name2)
{
	return !strncmp(f_name1, f_name2, FILENAME_LEN_DEFAULT);
}

static inline int proc_file(char *f_name)
{
	return !memcmp(f_name, "/proc", 5);
}

static inline int sys_file(char *f_name)
{
	return !memcmp(f_name, "/sys", 4);
}

static inline int dev_file(char *f_name)
{
	return !memcmp(f_name, "/dev", 4);
}

int proc_file_open(struct file *, char *f_name);
int sys_file_open(struct file *, char *f_name);
int dev_file_open(struct file *, char *f_name);

extern struct file_operations normal_p2s_f_ops;

static inline int normal_file_open(struct file *f, char *f_name)
{
	f->f_op = &normal_p2s_f_ops;
	return 0;
}

#endif /* _PROCESSOR_INCLUDE_FS_H_ */
