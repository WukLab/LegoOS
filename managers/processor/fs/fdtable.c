/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/fdtable.h>
#include <lego/slab.h>
#include <lego/sched.h>
//#include <lego/fs.h>

/* Close all files of current process */


static void close_files(struct files_struct * files)
{
	int i;
	for (i = 0; i < NR_OPEN_DEFAULT; i++){
		if (!IS_ERR(files->fd_array[i])){
			//lego_filp_close(files->fd_array[i]); /*not implemented*/
			//cond_resched();
		}
	}
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	task_lock(task);
	files = task->files;
	if (files)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
}

void put_files_struct(struct files_struct *files)
{
	//struct fdtable *fdt;

	if (atomic_dec_and_test(&files->count)) {
		close_files(files);
		kfree(files);
	}
}

void reset_files_struct(struct files_struct *files)
{
	struct task_struct *tsk = current;
	struct files_struct *old;

	old = tsk->files;
	task_lock(tsk);
	tsk->files = files;
	task_unlock(tsk);
	put_files_struct(old);
}


int __alloc_fd(struct files_struct *files,
	       unsigned start, unsigned end, unsigned flags)
{
	unsigned int fd;
	int error;
	struct file *f;

	spin_lock(&files->file_lock);
	fd = start;
repeat:
	if (fd < NR_OPEN_DEFAULT){
		f = files->fd_array[fd];
		if (!IS_ERR(f)){
			fd++;
			goto repeat;
		}	
	}
	
	if (fd >= end || fd == NR_OPEN_DEFAULT){
		error = -EMFILE;
		goto out;
	}
	error = fd;
out:
	spin_unlock(&files->file_lock);
	return error;
}

//int alloc_fd(){}

//int __close_fd(){
//}

void __fd_install(struct files_struct *files, unsigned int fd,
		struct file *file)
{
	struct file *f;
	spin_lock(&files->file_lock);
	BUG_ON(files->fd_array[fd] != NULL);
	files->fd_array[fd] = file;
	spin_unlock(&files->file_lock);
}
