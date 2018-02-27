/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/files.h>
#include <lego/sched.h>


static inline bool fd_is_open(int fd, struct files_struct *files)
{
	if (fd < NR_OPEN_DEFAULT && files->fd_array[fd]){
		return 1;
	}
	return 0;	
}



extern void __init files_defer_init(void);

static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;

	if (fd < NR_OPEN_DEFAULT && files->fd_array[fd])
		file = files->fd_array[fd];

	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

/*get files_struct from a task_struct*/
struct files_struct *get_files_struct(struct task_struct *);
void put_files_struct(struct files_struct *fs);
void reset_files_struct(struct files_struct *);
int unshare_files(struct files_struct **);
struct files_struct *dup_fd(struct files_struct *, int *);
void do_close_on_exec(struct files_struct *);
int iterate_fd(struct files_struct *, unsigned,
		int (*)(const void *, struct file *, unsigned),
		const void *);

extern int __alloc_fd(struct files_struct *files,
		      unsigned start, unsigned end, unsigned flags);
extern void __fd_install(struct files_struct *files,
		      unsigned int fd, struct file *file);
extern int __close_fd(struct files_struct *files,
		      unsigned int fd);

extern struct kmem_cache *files_cachep;


struct files_struct *get_files_struct(struct task_struct *);

extern struct file *get_empty_filp(void);




