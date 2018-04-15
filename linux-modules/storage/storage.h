/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_STORAGE_STORAGE_H_
#define _LEGO_STORAGE_STORAGE_H_

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/stat.h>

#include <asm/uaccess.h>
#include <asm/mman.h>

#include "common.h"

#define OP_SUCCESS		1
#define OP_FAILURE		0

#define MAX_USERS_ALLOWED 	2
#define MAX_FILE_NAME		256

#define FILE_METADATA		"/root/yilun/file_metadata.bin"

#define MAX_SIZE		2 


struct linux_dirent;

struct metadata {
	int			users[MAX_USERS_ALLOWED]; // Users who have access to this file
	int			noOfUsers;	// No of users accessing this file currently 
	fmode_t		permission; // The file permission applicable to all the users
	int			used;			// File descriptor
	int			owner;
	char		fileName[MAX_FILE_NAME];  	
};

typedef struct {
	// userID, fileName, service, length, offset, requesterInfo?, flags 
	int  		uid;
	char 		fileName[MAX_FILE_NAME]; // Requested file
	fmode_t		permission; // Permission for the data
	ssize_t 	len; 
	loff_t 		offset;
	int 		flags;
} request;

/* init.c */
extern struct metadata global_metadata[MAX_SIZE];
extern struct mutex metadata_lock;

/* metadata.c */
int get_metadata(void);
int update_metadata(void);
void dump_metadata(void);

/* permission.c */
int grant_access (request *, int *, int *);
int yield_access(int, int);
void test_grant_yield_access(void *);
request constuct_request(int, char *, fmode_t, ssize_t, loff_t, int);

/* file_ops.c */
struct file *local_file_open (request *);
int local_file_close(struct file *);
ssize_t local_file_write(struct file *, const char __user *, ssize_t, loff_t *);
ssize_t local_file_read(struct file *, char __user *, ssize_t, loff_t *);
int local_fsync(struct file *);
int kernel_fs_stat(const char *, struct kstat *, int);
int faccessat_root(const char __user *, int);
long do_unlink(const char *pathname);
long do_mkdir(const char *pathname, umode_t mode);
long do_rmdir(const char *pathname);
long do_kstatfs(const char *pathname, struct lego_kstatfs *statfsbuf);
long do_getdents(const char *pathname, struct linux_dirent *dirent,
		loff_t *pos, unsigned int count);
long do_readlink(const char *pathname, char *buf, int bufsiz);
long do_rename(char *oldname, char *newname);

/* handler.c */
int handle_open_request(void *, uintptr_t);
ssize_t handle_write_request(void *, uintptr_t);
ssize_t handle_read_request(void *, uintptr_t);
int handle_stat_request(void *, uintptr_t);
int handle_access_request(void *, uintptr_t);
long handle_truncate_request(void *, uintptr_t);
long handle_unlink_request(void *, uintptr_t);
long handle_mkdir_request(void *, uintptr_t);
long handle_rmdir_request(void *, uintptr_t);
long handle_statfs_request(void *payload, uintptr_t desc);
long handle_getdents_request(void *payload, uintptr_t desc);
long handle_readlink_request(void *payload, uintptr_t desc);
long handle_rename_request(void *payload, uintptr_t desc);
ssize_t handle_lseek_request(void *payload, uintptr_t desc);

/* m2s replica flush */
void handle_replica_flush(void *_msg, u64 desc);
void handle_replica_vma(void *_msg, u64 desc);

#endif /* _LEGO_STORAGE_STORAGE_H_ */
