/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

//#include <lego/fdtable.h>
#include <lego/slab.h>
//#include <lego/fs.h>
#include <lego/files.h>
#include <lego/printk.h>
#include <lego/comp_processor.h>
#include <lego/atomic.h>

#define NR_FILE 8192

atomic_t nr_files;
//atomic_set(&nr_files, 0);

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


int __alloc_fd(struct files_struct *files, unsigned start, unsigned end)
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

int alloc_fd(unsigned start){
	return __alloc_fd(current->files, start, NR_OPEN_DEFAULT);
}

/* This _close_fd will not close the file in storage side */

int __close_fd(struct files_struct *files, unsigned fd){
	//struct file *f;

	spin_lock(&files->file_lock);
	if (!files || fd >= NR_OPEN_DEFAULT)
		goto err;
	kfree(files->fd_array[fd]);
	files->fd_array[fd] = NULL;
	return 1;
err: 
	spin_unlock(&files->file_lock);
	return -EBADF;
}

int close_fd(unsigned fd){
	return __close_fd(current->files, fd);
}

void __fd_install(struct files_struct *files, unsigned fd,
		struct file *file)
{
	//struct file *f;
	spin_lock(&files->file_lock);
	BUG_ON(files->fd_array[fd] != NULL);
	files->fd_array[fd] = file;
	spin_unlock(&files->file_lock);
}

void fd_install(unsigned fd, struct file *file){
	return __fd_install(current->files, fd, file);	
}


struct file *get_empty_filp(void){
	struct file *f;

	if(atomic_read(&nr_files) < NR_FILE)
		goto over;
	
	f = kmalloc(sizeof(struct file), GFP_KERNEL);
	if(unlikely(!f))
		return ERR_PTR(-ENOMEM);
	mutex_init(&f->f_pos_lock);
	return f;
over:
	pr_info("MAX file count reaches.\n");
	return ERR_PTR(-ENFILE);

}

struct file *alloc_file(fmode_t mode, unsigned flags){
	struct file *f;

	f = get_empty_filp();
	if (IS_ERR(f))
		return f;
	f->f_mode = mode;
	f->f_flags = flags;
	return f;
}

void free_file(struct file *f){
	if (atomic_dec_and_test(&nr_files))
		goto err;
	kfree(f);
	return;
err: 
	pr_info("negative opened files\n");
	kfree(f);
	return;
}


struct file *lego_filp_open(const char *filename, int flags, umode_t mode){
	//send filename to memory
	//struct p2m_open_struct payload;
	int err, retbuf;
	BUG_ON(!filename);

	//strcpy(payload.filepath, filename);
	//payload.flags = flags;
	//payload.mode = mode;

	//net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_OPEN, &payload,
				//sizeof(payload), &retbuf, sizeof(retbuf), false,
				//DEF_NET_TIMEOUT);
	
	//printk();
	//the return buffer should contain the fileOpen result;
	//if error;
	//err = retbuf;
	//return ERR_PRT(err);
	
	//return alloc_file(mode, flags);
	
	//assume that remote open always success;
	return alloc_file(flags, mode);
	
}

long do_sys_open(const char *filename, int flags, umode_t mode){
	long fd;
	struct file *f;
	
	f = lego_filp_open(filename, flags, mode);
	if (IS_ERR(f))
		return PTR_ERR(f);
	fd = alloc_fd(0);
	if (fd >= 0){
		fd_install(fd, f);
	}
	return fd;
	//fd_install();
}



