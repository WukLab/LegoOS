/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RPC_STRUCT_M2M_H_
#define _LEGO_RPC_STRUCT_M2M_H_

#include <lego/rpc/struct_common.h>

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY 
/* M2M_MMAP */
struct m2m_mmap_struct {
	__u32	pid;
	__u64	new_range;
	__u64	addr;
	__u64	len;
	__u64	prot;
	__u64	flags;
	__u64	vm_flags;
	__u64	pgoff;
	char	f_name[MAX_FILENAME_LENGTH];
};
struct m2m_mmap_reply_struct {
	__u64 addr;
	__u64 max_gap;
};
int handle_m2m_mmap(struct m2m_mmap_struct *, u64, struct common_header *);

/* M2M_MUMMAP */
struct m2m_munmap_struct {
	__u32 pid;
	__u64 begin;
	__u64 len;
};
struct m2m_munmap_reply_struct {
	int status;
	__u64 max_gap;
};
int handle_m2m_munmap(struct m2m_munmap_struct *, u64, struct common_header *);

/* M2M_MREMAP_GROW */
struct m2m_mremap_grow_struct {
	__u32	pid;
	__u64	addr;
	__u64	old_len;
	__u64	new_len;
};
struct m2m_mremap_grow_reply_struct {
	int status;
	__u64 max_gap;
};
int handle_m2m_mremap_grow(struct m2m_mremap_grow_struct *, u64, struct common_header *);

/* M2M_MREMAP_MOVE */
struct m2m_mremap_move_struct {
	__u32	pid;
	__u64	old_addr;
	__u64	old_len;
	__u64	new_len;
	__u64	new_range;
};
struct m2m_mremap_move_reply_struct {
	__u64 new_addr;
	__u64 old_max_gap;
	__u64 new_max_gap;
};
int handle_m2m_mremap_move(struct m2m_mremap_move_struct *, u64, struct common_header *);

/* M2M_MREMAP_MOVE_SPLIT */
struct m2m_mremap_move_split_struct {
	__u32	pid;
	__u64	old_addr;
	__u64	old_len;
	__u64	new_addr;
	__u64	new_len;
};
struct m2m_mremap_move_split_reply_struct {
	__u64 new_addr;
	__u64 old_max_gap;
	__u64 new_max_gap;
};
int handle_m2m_mremap_move_split(struct m2m_mremap_move_split_struct *, 
				 u64, struct common_header *);

/* M2M_FINDVMA */
struct m2m_findvma_struct {
	__u32 pid;
	__u64 begin;
	__u64 end;
};
struct m2m_findvma_reply_struct {
	int vma_exist;
};
int handle_m2m_findvma(struct m2m_findvma_struct *, u64, struct common_header *);

/* M2M_MSYNC */
struct m2m_msync_struct {
	__u32	pid;
	__u64	start;
	__u64	len;
	__u32	flags;
};
int handle_m2m_msync(struct m2m_msync_struct *, u64, struct common_header *);
#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */

#endif /* _LEGO_RPC_STRUCT_M2M_H_ */
