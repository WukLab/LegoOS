/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RPC_STRUCT_P2S_H
#define _LEGO_RPC_STRUCT_P2S_H

#include <lego/rpc/struct_common.h>
#include <lego/stat.h>
#include <processor/statfs.h>

struct p2s_open_struct{
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	fmode_t	permission;
	int	flags;
};

struct p2s_access_struct {
	char filename[MAX_FILENAME_LENGTH];
	int mode;
};

struct p2s_stat_struct {
	char filename[MAX_FILENAME_LENGTH];
	int flag;
};

struct p2s_stat_ret_struct {
	int retval;
	struct kstat statbuf;
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
	struct lego_kstatfs kstatfs;
};

struct p2s_getdents_struct {
	char filename[MAX_FILENAME_LENGTH];
	loff_t pos;
	unsigned int count;
};

struct p2s_getdents_retval_struct {
	long retval;
	loff_t pos;
};

struct p2s_readlink_struct {
	char filename[MAX_FILENAME_LENGTH];
	int bufsiz;
};

struct p2s_rename_struct {
	char oldname[MAX_FILENAME_LENGTH];
	char newname[MAX_FILENAME_LENGTH];
};

#endif /* _LEGO_RPC_STRUCT_P2S_H */
