/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RPC_STRUCT_P2M_H
#define _LEGO_RPC_STRUCT_P2M_H

#include <memory/replica_types.h>
#include <processor/pcache_config.h>
#include <lego/rpc/struct_common.h>
#include <lego/mmap.h>

struct thpool_buffer;

struct p2m_test_msg {
	struct common_header	header;
	__u32			send_len;
	__u32			reply_len;
};
void handle_p2m_test(struct p2m_test_msg *msg, struct thpool_buffer *tb);
void handle_p2m_test_noreply(struct p2m_test_msg *msg, struct thpool_buffer *tb);

/*
 * P2M_ZEROFILL
 */
struct p2m_zerofill_msg {
	struct common_header	header;
	__u32			pid;
	__u32			tgid;
	__u32			flags;
	__u64			missing_vaddr;
};
void handle_p2m_zerofill(struct p2m_zerofill_msg *msg,
			 struct thpool_buffer *tb);

/* P2M_PCACHE_FLUSH */
struct p2m_flush_msg {
	struct common_header	header;
	u32			pid;
	unsigned long		user_va;
	char			pcacheline[PCACHE_LINE_SIZE];
};

void handle_p2m_flush_one(struct p2m_flush_msg *msg, struct thpool_buffer *tb);

/*
 * P2M_MISS
 */

struct p2m_pcache_miss_msg {
	struct common_header	header;
	unsigned int		has_flush_msg;
	__u32			pid;
	__u32			tgid;
	__u32			flags;
	__u64			missing_vaddr;
};

struct p2m_pcache_miss_flush_combine_msg {
	struct p2m_pcache_miss_msg	miss;
	struct p2m_flush_msg		flush;
};

#define PCACHE_MAPPING_ANON	0x1
#define PCACHE_MAPPING_FILE	0x2

/* For debug only */
struct p2m_pcache_miss_reply_struct {
	__u32	mapping_flags;
	__wsum	csum;
	char	data[PCACHE_LINE_SIZE];
};

void handle_p2m_pcache_miss(struct p2m_pcache_miss_msg *msg,
			    struct thpool_buffer *b);

struct p2m_replica_msg {
	struct common_header	header;
	struct replica_log	log;
} __packed __aligned(8);
void handle_p2m_replica(void *_msg, struct thpool_buffer *tb);

/*
 * P2M_READ
 * P2M_WRITE
 */

/*
 * We need pass the filename, uid, flags, len, offset
 * and virtual address of user buffer to memory component
 * Also we need nid and pid to convert user virtual address
 * to coresponding kernel virtual address.
 */
struct p2m_read_write_payload {
	u32	pid;
	u32	tgid;
	char __user *buf;
	int	uid;
	__u32	storage_node;
	char	filename[MAX_FILENAME_LENGTH];
	int	flags;
	ssize_t	len;
	loff_t	offset;
};
void handle_p2m_read(struct p2m_read_write_payload *payload,
		     struct common_header *hdr, struct thpool_buffer *tb);
void handle_p2m_write(struct p2m_read_write_payload *payload,
		      struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_CLOSE
 */
struct p2m_close_struct {
	__u32 pid;
};
int handle_p2m_close(struct p2m_close_struct *, u64, struct common_header *);

/*
 * P2M_FORK
 */
/* Task command name length */
#define LEGO_TASK_COMM_LEN 16

struct p_vm_area_struct {
	__u64	vm_start;
	__u64	vm_end;
	__u64	vm_flags;
};

struct p2m_fork_struct {
	__u32	pid;
	__u32	tgid;
	__u32	parent_tgid;
	__u32	clone_flags;
	char	comm[LEGO_TASK_COMM_LEN];
};

/* Below two struct are used in both m2m and p2m */
struct fork_vmainfo {
	unsigned long	vm_start;
	unsigned long	vm_end;
	unsigned long	vm_flags;
} __packed;

struct fork_reply_struct {
	int			ret;
	u32			vma_count;
	struct fork_vmainfo	vmainfos[DEFAULT_MAX_MAP_COUNT];
} __packed;

struct task_struct;
void *p2m_fork(struct task_struct *p, unsigned long clone_flags);
void handle_p2m_fork(struct p2m_fork_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_EXECVE
 */
/*
 * These are the maximum length and maximum number of strings passed to the
 * execve() system call.  MAX_ARG_STRLEN is essentially random but serves to
 * prevent the kernel from being unduly impacted by misaddressed pointers.
 * MAX_ARG_STRINGS is chosen to fit in a signed 32-bit integer.
 */
#define MAX_ARG_STRLEN		(PAGE_SIZE * 32)
#define MAX_ARG_STRINGS		0x7FFFFFFF

struct p2m_execve_struct {
	__u32	pid;
	__u32	payload_size;
	char	filename[MAX_FILENAME_LENGTH];
	__u32	argc;
	__u32	envc;
	char	*array;
	/*
	 * NOTE:
	 * variable size struct
	 * the @payload_size means the total size
	 */
};
struct m2p_execve_struct {
	__u32	status;
	__u64	new_ip;
	__u64	new_sp;
#ifdef CONFIG_DISTRIBUTED_VMA
	struct vmr_map_reply map;
#endif
};
void handle_p2m_execve(struct p2m_execve_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_MMAP
 */
struct p2m_mmap_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
	__u64	prot;
	__u64	flags;
	__u64	pgoff;
	char	f_name[MAX_FILENAME_LENGTH];
};
struct p2m_mmap_reply_struct {
	int	ret;
	__u64	ret_addr;
#ifdef CONFIG_DISTRIBUTED_VMA
	struct vmr_map_reply map;
#endif
};
void handle_p2m_mmap(struct p2m_mmap_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_MUNMAP
 */
struct p2m_munmap_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
};
struct p2m_munmap_reply_struct {
	int	ret;
#ifdef CONFIG_DISTRIBUTED_VMA
	struct vmr_map_reply map;
#endif
};

void handle_p2m_munmap(struct p2m_munmap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_MREMAP
 */
struct p2m_mremap_struct {
	__u32	pid;
	__u64	old_addr;
	__u64	old_len;
	__u64	new_len;
	__u64	flags;
	__u64	new_addr;
};
struct p2m_mremap_reply_struct {
	int	status;
	__u32	line;			/* which line fails... */
	__u64	new_addr;
#ifdef CONFIG_DISTRIBUTED_VMA
	struct vmr_map_reply map;
#endif
};
void handle_p2m_mremap(struct p2m_mremap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_MPROTECT
 */
struct p2m_mprotect_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
	__u32	prot;
};
void handle_p2m_mprotect(struct p2m_mprotect_struct *payload,
			 struct thpool_buffer *tb);

/*
 * P2M_BRK
 */
struct p2m_brk_struct {
	__u32	pid;
	__u64	brk;
};
struct p2m_brk_reply_struct {
	__u64	ret_brk;
#ifdef CONFIG_DISTRIBUTED_VMA
	struct vmr_map_reply map;
#endif
};
void handle_p2m_brk(struct p2m_brk_struct *payload,
		    struct common_header *hdr, struct thpool_buffer *tb);

/*
 * P2M_MSYNC
 */
#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */
struct p2m_msync_struct {
	__u32	pid;
	__u64	start;
	__u64	len;
	__u32	flags;
};
int handle_p2m_msync(struct p2m_msync_struct *, u64, struct common_header *, void *);

/*
 * P2M_CHECKPOINT
 */
int handle_p2m_checkpint(void *, u64, struct common_header *);

void handle_p2m_drop_page_cache(struct common_header *hdr, struct thpool_buffer *tb);

#ifdef CONFIG_MEM_PAGE_CACHE
struct p2m_lseek_struct {
	char filename[MAX_FILENAME_LENGTH];
	__u32 storage_node;
};
int handle_p2m_lseek(struct p2m_lseek_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb);

struct p2m_rename_struct {
	char oldname[MAX_FILENAME_LENGTH];
	char newname[MAX_FILENAME_LENGTH];
	__u32 storage_node;
};

int handle_p2m_rename(struct p2m_rename_struct *payload,
		      struct common_header *hdr, struct thpool_buffer *tb);

struct p2m_stat_struct {
	char filename[MAX_FILENAME_LENGTH];
	int flag;
	__u32 storage_node;
};
int handle_p2m_stat(struct p2m_stat_struct *payload,
		    struct common_header *hdr, struct thpool_buffer *tb);
#endif /* CONFIG_MEM_PAGE_CACHE */

struct p2m_fsync_struct {
	char filename[MAX_FILENAME_LENGTH];
	__u32 storage_node;
};

#endif /* _LEGO_RPC_STRUCT_P2M_H */
