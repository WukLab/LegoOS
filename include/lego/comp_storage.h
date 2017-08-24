/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Things shared by both processor-component and storage-component
 */

#ifndef _LEGO_COMP_STORAGE_H_
#define _LEGO_COMP_STORAGE_H_

#include <lego/comp_common.h>

#define M2S_OPEN ((__u32)(M2S_BASE)+3)

#define DEBUG_STORAGE

/* we need pass the filename, uid, flags, len, offset
 * and virtual address of user buffer to memory component
 * Also we need nid and pid to convert user virtual address
 * to coresponding kernel virtual address.
 */

struct p2m_read_write_payload{
	int pid;
	char __user *buf;
	int uid;
	char filename[MAX_FILENAME_LENGTH];
	int flags;
	ssize_t len;
	loff_t offset;
};

struct m2s_open_payload{
	int uid;
	char filename[MAX_FILENAME_LENGTH];
	fmode_t permission;
	int flags;
};

struct m2s_read_write_payload{
	int uid;
	char filename[MAX_FILENAME_LENGTH];
	int flags;
	size_t len;
	loff_t offset;
};

ssize_t handle_p2s_read(void *payload, uintptr_t desc, struct common_header *hdr);
ssize_t handle_p2s_write(void *payload, uintptr_t desc, struct common_header *hdr);

void p2s_test(void);
void m2s_test(void);

#endif
