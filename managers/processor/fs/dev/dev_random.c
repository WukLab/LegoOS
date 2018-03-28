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
#include <lego/random.h>
#include <processor/processor.h>
#include <processor/fs.h>

static int random_open(struct file *f)
{
	/* Always present */
	return 0;
}

static ssize_t random_read(struct file *f, char __user *buf,
			   size_t count, loff_t *off)
{
	void *k_buffer;
	ssize_t ret;

	if (!count)
		return 0;

	k_buffer = kmalloc(count, GFP_KERNEL);
	if (!k_buffer)
		return -ENOMEM;

	ret = count;
	get_random_bytes(k_buffer, count);
	if (copy_to_user(buf, k_buffer, count))
		ret = -EFAULT;

	kfree(k_buffer);
	return ret;
}

static ssize_t random_write(struct file *f, const char __user *buf,
			    size_t count, loff_t *off)
{
	return -EFAULT;
}

struct file_operations random_file_ops = {
	.llseek	= dev_llseek,
	.open	= random_open,
	.read	= random_read,
	.write	= random_write,
};

static int urandom_open(struct file *f)
{
	/* Always present */
	return 0;
}

static ssize_t urandom_read(struct file *f, char __user *buf,
			    size_t count, loff_t *off)
{
	void *k_buffer;
	ssize_t ret;

	if (!count)
		return 0;

	k_buffer = kmalloc(count, GFP_KERNEL);
	if (!k_buffer)
		return -ENOMEM;

	ret = count;
	get_random_bytes(k_buffer, count);
	if (copy_to_user(buf, k_buffer, count))
		ret = -EFAULT;

	kfree(k_buffer);
	return ret;
}

static ssize_t urandom_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *off)
{
	return -EFAULT;
}

struct file_operations urandom_file_ops = {
	.llseek	= dev_llseek,
	.open	= urandom_open,
	.read	= urandom_read,
	.write	= urandom_write,
};
