/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_FILES_H_
#define _LEGO_FILES_H_

#include <lego/slab.h>
#include <lego/mutex.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/fcntl.h>

#define SEEK_SET	0	/* seek relative to beginning of file */
#define SEEK_CUR	1	/* seek relative to current file position */
#define SEEK_END	2	/* seek relative to end of file */
#define SEEK_DATA	3	/* seek to the next data */
#define SEEK_HOLE	4	/* seek to the next hole */
#define SEEK_MAX	SEEK_HOLE

/*
 * flags in file.f_mode.  Note that FMODE_READ and FMODE_WRITE must correspond
 * to O_WRONLY and O_RDWR via the strange trick in __dentry_open()
 */

/* file is open for reading */
#define FMODE_READ		((__force fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE		((__force fmode_t)0x2)
/* file is seekable */
#define FMODE_LSEEK		((__force fmode_t)0x4)
/* file can be accessed using pread */
#define FMODE_PREAD		((__force fmode_t)0x8)
/* file can be accessed using pwrite */
#define FMODE_PWRITE		((__force fmode_t)0x10)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC		((__force fmode_t)0x20)
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY		((__force fmode_t)0x40)
/* File is opened with O_EXCL (only set for block devices) */
#define FMODE_EXCL		((__force fmode_t)0x80)
/* File is opened using open(.., 3, ..) and is writeable only for ioctls
   (specialy hack for floppy.c) */
#define FMODE_WRITE_IOCTL	((__force fmode_t)0x100)
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH         ((__force fmode_t)0x200)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH         ((__force fmode_t)0x400)

/*
 * Don't update ctime and mtime.
 *
 * Currently a special hack for the XFS open_by_handle ioctl, but we'll
 * hopefully graduate it to a proper O_CMTIME flag supported by open(2) soon.
 */
#define FMODE_NOCMTIME		((__force fmode_t)0x800)

/* Expect random access pattern */
#define FMODE_RANDOM		((__force fmode_t)0x1000)

/* File is huge (eg. /dev/kmem): treat loff_t as unsigned */
#define FMODE_UNSIGNED_OFFSET	((__force fmode_t)0x2000)

/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH		((__force fmode_t)0x4000)

/* File needs atomic accesses to f_pos */
#define FMODE_ATOMIC_POS	((__force fmode_t)0x8000)
/* Write access to underlying fs */
#define FMODE_WRITER		((__force fmode_t)0x10000)
/* Has read method(s) */
#define FMODE_CAN_READ          ((__force fmode_t)0x20000)
/* Has write method(s) */
#define FMODE_CAN_WRITE         ((__force fmode_t)0x40000)

/* File was opened by fanotify and shouldn't generate fanotify events */
#define FMODE_NONOTIFY		((__force fmode_t)0x4000000)


#define FILENAME_LEN_DEFAULT	256
struct file;

struct file_system{
	int users;
	char cwd[FILENAME_LEN_DEFAULT];
	char root[FILENAME_LEN_DEFAULT];
	spinlock_t lock;
	int umask;
};

struct file_operations {
	loff_t		(*llseek)(struct file *, loff_t, int);
	int		(*open)(struct file *);
	ssize_t 	(*read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t 	(*write)(struct file *, const char __user *, size_t, loff_t *);
	int		(*release) (struct file *);
	unsigned int	(*poll)(struct file *);
};


struct file {
	fmode_t			f_mode;
	atomic_t		f_count;
	unsigned int 		f_flags;
	spinlock_t		f_pos_lock;
	loff_t			f_pos;
	char			f_name[FILENAME_LEN_DEFAULT];
	int			fd;
	const struct file_operations *f_op;

#ifdef CONFIG_EPOLL
	struct list_head	f_epi_links;
#endif

	/* for poll */
	struct list_head	f_poll_links;

	/* shared by poll, and epoll if configured */
	int			ready_state;
	int			ready_size;

	void			*private_data;
};

#define NR_OPEN_DEFAULT		64

/* Opened files table structure */
struct files_struct {
	atomic_t count;

	spinlock_t file_lock ____cacheline_aligned_in_smp;

	/*
	 * @fd_bitmap is used for fast search
	 * @fd_array is the real pointer array
	 *
	 * Both protected by @file_lock above
	 */
	DECLARE_BITMAP(close_on_exec, NR_OPEN_DEFAULT);
	DECLARE_BITMAP(fd_bitmap, NR_OPEN_DEFAULT);
	struct file *fd_array[NR_OPEN_DEFAULT];
} ____cacheline_aligned;

static inline bool close_on_exec(unsigned int fd, struct files_struct *fs)
{
	return test_bit(fd, fs->close_on_exec);
}

bool get_close_on_exec(unsigned int fd);
void set_close_on_exec(unsigned int fd, int flag);

static inline void __set_close_on_exec(unsigned int fd, struct files_struct *fs)
{
	__set_bit(fd, fs->close_on_exec);
}

static inline void __clear_close_on_exec(unsigned int fd, struct files_struct *fs)
{
	if (test_bit(fd, fs->close_on_exec))
		__clear_bit(fd, fs->close_on_exec);
}

struct iovec {
	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
	unsigned long iov_len;	/* Must be size_t (1003.1g) */
};

/*
 * UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
 */
#define UIO_FASTIOV	8
#define UIO_MAXIOV	1024

static inline bool pipe_file(char *filename)
{
	return !memcmp(filename, "PIPE", 4);
}

static inline void get_file(struct file *filp)
{
	atomic_inc(&filp->f_count);
}

static inline void __put_file(struct file *filp)
{
	BUG_ON(atomic_read(&filp->f_count) != 0);
	kfree(filp);
}

static inline void put_file(struct file *filp)
{
	if (atomic_dec_and_test(&filp->f_count))
		__put_file(filp);
}

int get_absolute_pathname(int dfd, char *k_pathname, const char __user *pathname);

#ifdef CONFIG_MEM_PAGE_CACHE
ssize_t get_file_size(const char *pathname);
#endif

/*
 * arch dependent, long for x86_64
 */
#define __statfs_word long

struct statfs {
	__statfs_word f_type;
	__statfs_word f_bsize;
	__statfs_word f_blocks;
	__statfs_word f_bfree;
	__statfs_word f_bavail;
	__statfs_word f_files;
	__statfs_word f_ffree;
	__kernel_fsid_t f_fsid;
	__statfs_word f_namelen;
	__statfs_word f_frsize;
	__statfs_word f_flags;
	__statfs_word f_spare[4];
};

#endif /* _LEGO_FILES_H_ */
