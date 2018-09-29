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
	u32		pid;
	u32		prcsr_nid;
	unsigned long	new_range;
	unsigned long	addr;
	unsigned long	len;
	unsigned long	prot;
	unsigned long	flags;
	vm_flags_t	vm_flags;
	unsigned long	pgoff;
	char		f_name[MAX_FILENAME_LENGTH];
};
struct m2m_mmap_reply_struct {
	unsigned long	addr;
	unsigned long	max_gap;
};
void handle_m2m_mmap(struct m2m_mmap_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_MUMMAP */
struct m2m_munmap_struct {
	u32		pid;
	u32		prcsr_nid;
	unsigned long	begin;
	unsigned long	len;
};
struct m2m_munmap_reply_struct {
	int status;
	unsigned long	max_gap;
};
void handle_m2m_munmap(struct m2m_munmap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_MREMAP_GROW */
struct m2m_mremap_grow_struct {
	u32		pid;
	u32		prcsr_nid;
	unsigned long	addr;
	unsigned long	old_len;
	unsigned long	new_len;
};
struct m2m_mremap_grow_reply_struct {
	int status;
	unsigned long max_gap;
};
void handle_m2m_mremap_grow(struct m2m_mremap_grow_struct *payload,
			    struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_MREMAP_MOVE */
struct m2m_mremap_move_struct {
	u32		pid;
	u32		prcsr_nid;
	unsigned long	old_addr;
	unsigned long	old_len;
	unsigned long	new_len;
	unsigned long	new_range;
};
struct m2m_mremap_move_reply_struct {
	unsigned long	new_addr;
	unsigned long	old_max_gap;
	unsigned long	new_max_gap;
};
void handle_m2m_mremap_move(struct m2m_mremap_move_struct *payload,
			   struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_MREMAP_MOVE_SPLIT */
struct m2m_mremap_move_split_struct {
	u32		pid;
	u32		prcsr_nid;
	unsigned long	old_addr;
	unsigned long	old_len;
	unsigned long	new_addr;
	unsigned long	new_len;
};
struct m2m_mremap_move_split_reply_struct {
	unsigned long	new_addr;
	unsigned long	old_max_gap;
	unsigned long	new_max_gap;
};
void handle_m2m_mremap_move_split(struct m2m_mremap_move_split_struct *payload,
				  struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_FINDVMA */
struct m2m_findvma_struct {
	u32		pid;
	u32		prcsr_nid;
	unsigned long	begin;
	unsigned long	end;
};
struct m2m_findvma_reply_struct {
	int vma_exist;
};
void handle_m2m_findvma(struct m2m_findvma_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_MSYNC */
struct m2m_msync_struct {
	u32		pid;
	u32		prcsr_nid;
	unsigned long	start;
	unsigned long	len;
	unsigned long	flags;
};
void handle_m2m_msync(struct m2m_msync_struct *payload,
		      struct common_header *hdr, struct thpool_buffer *tb);

/* M2M_FORK */
struct m2m_fork_struct {
	u32		parent_pid;
	u32		child_pid;
	u32		prcsr_nid;
};
void handle_m2m_fork(struct m2m_fork_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb);

#ifdef CONFIG_DEBUG_VMA
struct m2m_validate_struct {
	u32		prcsr_nid;
	u32		pid;
	unsigned long	addr;
	unsigned long	len;
};
void handle_m2m_validate(struct m2m_validate_struct *payload,
			 struct common_header *hdr, struct thpool_buffer *tb);
#endif

#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */

#endif /* _LEGO_RPC_STRUCT_M2M_H_ */
