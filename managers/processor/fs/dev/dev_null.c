/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/files.h>
#include <processor/processor.h>
#include <processor/fs.h>

static int null_open(struct file *f)
{
	/* Always present */
	return 0;
}

static ssize_t null_read(struct file *f, char __user *buf,
			size_t count, loff_t *off)
{
	/* Always return 0 */
	return 0;
}

static ssize_t null_write(struct file *f, const char __user *buf,
			size_t count, loff_t *off)
{
	/* Do nothing, always return count */
	return count;
}

struct file_operations null_file_ops = {
	.llseek = dev_llseek,
	.open = null_open,
	.read = null_read,
	.write = null_write,
};
