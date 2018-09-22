/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PGCACHE_H_
#define _LEGO_PGCACHE_H_

#include <lego/kernel.h>
#include <lego/slab.h>
#include <lego/comp_memory.h>
#include <lego/comp_common.h>
#include <memory/task.h>
#include <memory/thread_pool.h>
#include <lego/types.h>

#ifdef CONFIG_DEBUG_PAGE_CACHE
#define pgcache_debug(fmt, ...) 			\
	pr_debug("%s() "fmt"\n",			\
			__func__, __VA_ARGS__)
#else
static inline void pgcache_debug(const char *fmt, ...) {  }
#endif /* CONFIG_DEBUG_PAGE_CACHE */

#define PGCACHE_HASH_BITS	10
#define PGCACHE_PREFETCH_ORDER	6 /* How many pages to read to page cache while cache miss */

#define CL_SIZE			(PAGE_SIZE*(1 << PGCACHE_PREFETCH_ORDER))
#define POS_MASK		~(CL_SIZE - 1)
#define aligned_pos(x)		x & POS_MASK
#define chunk_offset(x)		x & (~POS_MASK)

struct lego_pgcache_struct {

	loff_t			pos;		/* aligned pos */
	char 			filepath[MAX_FILENAME_LENGTH];
	u32 			real_len;	/* real length is likely to be smaller than
						 * cacheline size if file size is small */
	spinlock_t 		lock;		/* lock to protect lego_pgcache_struct */
	bool 			dirty;
	bool 			hir;		/* this cacheline is HIR */

	unsigned int 		storage_node;	/* cached result of storage node of this cacheline */

	struct hlist_node 	link;
	
	struct list_head 	dirtylist;
	
	struct list_head 	stack_s;	/* list of lirs_stack_s */
	
	struct list_head 	stack_q;	/* list of lirs_stack_q */

	void 			*cached_pages;	/* cached file blocks */

};

struct lego_pgcache_file {
	char 			filepath[MAX_FILENAME_LENGTH];	
							/* filepath */
	struct hlist_node 	hlink;
	struct list_head 	head;			/* head of a file's dirtlist */
	size_t			f_size;			/* up-to-date file size */
	spinlock_t 		dirtylist_lock;

	unsigned int 		storage_node;		/* will be used later */
};

/* alloc.c */
struct lego_pgcache_struct *__alloc_pgcache(char *filepath, loff_t pos,
		unsigned int storage_node);
void __free_pgcache_locked(struct lego_pgcache_struct *pgc);
void __free_pgcache_struct(struct lego_pgcache_struct *pgc);

/* hlist.c */
int ht_insert_lego_pgcache_struct(struct lego_pgcache_struct *pgc);
void ht_remove_lego_pgcache_struct(struct lego_pgcache_struct *pgc);
void free_lego_pgcache_struct(struct lego_pgcache_struct *pgc);
struct lego_pgcache_struct *							\
	find_lego_pgcache_struct(char *filepath, loff_t pos);
int drop_pgcache(void);

/* dirtylist.c */
struct lego_pgcache_file *lego_pgcache_file_open(char *filepath,		\
		unsigned int storage_node);

int ht_insert_lego_pgcache_file(struct lego_pgcache_file *file);
void ht_remove_lego_pgcache_file(struct lego_pgcache_file *file);
void free_lego_pgcache_file(struct lego_pgcache_file *file);
struct lego_pgcache_file *find_lego_pgcache_file(char *filepath);

void mark_lego_pgcache_dirty(struct lego_pgcache_struct *pgc,			\
			struct lego_pgcache_file *file);
void make_lego_pgcache_clean(struct lego_pgcache_struct *pgc);
int handle_p2m_fsync(char *payload, struct common_header *hdr, 			\
		     struct thpool_buffer *tb);

/* read_write.c */
ssize_t flush_one_cacheline_locked(struct lego_pgcache_struct *pgc);
ssize_t lego_pgcache_read(struct lego_task_struct *tsk, char *f_name,		\
		unsigned int storage_node, char __user *buf,			\
		size_t count, loff_t *pos);

ssize_t lego_pgcache_write(struct lego_task_struct *tsk, char *f_name,	\
		unsigned int storage_node, char __user *buf,			\
		size_t count, loff_t *pos);

/* eviction.c */
void update_lirs_structure(struct lego_pgcache_struct *pgc);
void pgcache_evict_one(void);

ssize_t get_file_size_from_storage(char *filepath, unsigned int storage_node);

static inline size_t file_size_read(struct lego_pgcache_file *file)
{
	size_t ret;

	spin_lock(&file->dirtylist_lock);
	ret = file->f_size;
	spin_unlock(&file->dirtylist_lock);

	return ret;
}

#endif /* _LEGO_PGCACHE_H_ */
