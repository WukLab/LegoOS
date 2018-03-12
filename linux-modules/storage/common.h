/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/statfs.h>

//#include "../../include/lego/comp_common.h"

#define BLK_SIZE 5*4096

/* fit module */
int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int if_use_ret_phys_addr);
int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);
int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);

/* copy from lego comp_common.h */
/* Processor to Storage directly */
#define P2S_OPEN	((__u32)__NR_open)	/* open() goes to storage directly */
#define P2S_STAT	((__u32)__NR_stat)
#define P2S_ACCESS	((__u32)__NR_access)
#define P2S_TRUNCATE	((__u32)__NR_truncate)
#define P2S_UNLINK	((__u32)__NR_unlink)
#define P2S_MKDIR	((__u32)__NR_mkdir)
#define P2S_RMDIR	((__u32)__NR_rmdir)
#define P2S_STATFS	((__u32)__NR_statfs)
#define P2S_GETDENTS	((__u32)__NR_getdents)
#define P2S_READLINK	((__u32)__NR_readlink)

/* Memory to Storage */
#define M2S_READ	((__u32)__NR_read)
#define M2S_WRITE	((__u32)__NR_write)
#define MAX_FILENAME_LENGTH	128

/* P2S_OPEN */
struct p2s_open_struct{
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	fmode_t	permission;
	int	flags;
};

/* M2S_READ */
/* M2S_WRITE */
struct m2s_read_write_payload{
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	int	flags;
	size_t	len;
	loff_t	offset;
};


struct p2s_access_struct {
	char filename[MAX_FILENAME_LENGTH];
	int mode;
};

struct p2s_stat_struct {
	char filename[MAX_FILENAME_LENGTH];
	int flag;
};

struct p2s_truncate_struct {
	char filename[MAX_FILENAME_LENGTH];
	long length;
};

struct p2s_unlink_struct {
	char filename[MAX_FILENAME_LENGTH];
};

struct p2s_mkdir_struct {
	char filename[MAX_FILENAME_LENGTH];
	umode_t mode;
};

struct p2s_rmdir_struct {
	char filename[MAX_FILENAME_LENGTH];
};

struct p2s_statfs_struct {
	char filename[MAX_FILENAME_LENGTH];
};

struct p2s_statfs_ret_struct {
	long retval;
	struct kstatfs kstatfs;
};

struct p2s_getdents_struct {
	char filename[MAX_FILENAME_LENGTH];
	loff_t pos;
	unsigned int count;
};

/* getdents */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct p2s_getdents_retval_struct {
	long retval;
	loff_t pos;
};

struct p2s_readlink_struct {
	char filename[MAX_FILENAME_LENGTH];
	int bufsiz;	
};
