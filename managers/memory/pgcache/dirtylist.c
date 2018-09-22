/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/list.h>
#include <lego/spinlock.h>
#include <lego/timer.h>
#include <memory/pgcache.h>
#include <lego/hashtable.h>
#include <lego/fit_ibapi.h>

/* lock to protect pgcache dirtylist struct */

static DEFINE_SPINLOCK(hash_dirtylists_lock);
static DEFINE_HASHTABLE(hash_dirtylists, PGCACHE_HASH_BITS);

static unsigned int get_key(char *str)
{
	unsigned int seed = 131;
	unsigned int hash = 0;

	while (*str) {
		hash = hash*seed + (*str++);
	}

	return hash & 0x7fffffff;
}

struct lego_pgcache_file *lego_pgcache_file_open(char *filepath,
		unsigned int storage_node)
{
	struct lego_pgcache_file *file;
	ssize_t tmp_file_size;

	file = kzalloc(sizeof(*file), GFP_KERNEL);
	if (unlikely(!file)) {
		return ERR_PTR(-ENOMEM);
	}

	strcpy(file->filepath, filepath);
	file->storage_node = storage_node;

	tmp_file_size = get_file_size_from_storage(filepath, storage_node);
	if (likely(tmp_file_size >= 0))
		file->f_size = tmp_file_size;

	INIT_LIST_HEAD(&file->head);
	spin_lock_init(&file->dirtylist_lock);

	return file;
}

int ht_insert_lego_pgcache_file(struct lego_pgcache_file *file)
{
	struct lego_pgcache_file *p;
	unsigned int key;

	BUG_ON(!file || strlen(file->filepath) == 0);

	pgcache_debug("filepath: %s", file->filepath);

	key = get_key(file->filepath);

	spin_lock(&hash_dirtylists_lock);
	hash_for_each_possible(hash_dirtylists, p, hlink, key) {
		if (unlikely(strcmp(p->filepath, file->filepath) == 0)) {
			spin_unlock(&hash_dirtylists_lock);
			return -EEXIST;
		}
	}
	hash_add(hash_dirtylists, &file->hlink, key);
	spin_unlock(&hash_dirtylists_lock);

	return 0;
}

void ht_remove_lego_pgcache_file(struct lego_pgcache_file *file)
{
	BUG_ON(!file || strlen(file->filepath) == 0);
	spin_lock(&hash_dirtylists_lock);
	hash_del(&file->hlink);
	spin_unlock(&hash_dirtylists_lock);
}

// should not be called
void free_lego_pgcache_file(struct lego_pgcache_file *file)
{
	struct lego_pgcache_file *p;
	unsigned int key;

	BUG_ON(!file || strlen(file->filepath) == 0);

	key = get_key(file->filepath);

	spin_lock(&hash_dirtylists_lock);
	hash_for_each_possible(hash_dirtylists, p, hlink, key) {
		if (likely(strcmp(p->filepath, file->filepath) == 0)) {

			hash_del(&p->hlink);
			kfree(p);
			spin_unlock(&hash_dirtylists_lock);
			return;
		}
	}
	spin_unlock(&hash_dirtylists_lock);
	WARN(1, "Fail to find file->(filepath:%s)\n", file->filepath);
	return;
}

struct lego_pgcache_file *find_lego_pgcache_file(char *filepath)
{
	struct lego_pgcache_file *file;
	unsigned int key;

	if (unlikely(strlen(filepath) == 0))
		return NULL;

	key = get_key(filepath);

	spin_lock(&hash_dirtylists_lock);
	hash_for_each_possible(hash_dirtylists, file, hlink, key) {
		if (likely(strcmp(file->filepath, filepath) == 0)) {
			spin_unlock(&hash_dirtylists_lock);

			pgcache_debug("file: %p", file);

			return file;
		}
	}
	spin_unlock(&hash_dirtylists_lock);

	return NULL;
}

void mark_lego_pgcache_dirty(struct lego_pgcache_struct *pgc,
		struct lego_pgcache_file *file)
{
	BUG_ON(!pgc || !file || IS_ERR(file));

	spin_lock(&pgc->lock);
	/* already marked as dirty */
	if (pgc->dirty) {
		spin_unlock(&pgc->lock);
		return;
	}

	spin_lock(&file->dirtylist_lock);
	/* mark as dirty cacheline*/
	pgc->dirty = true;
	/* add to dirty list */
	list_add(&pgc->dirtylist, &file->head);
	pgcache_debug("pgc: %p, head: %p, pgc->next: %p",		\
			pgc, &file->head, pgc->dirtylist.next);

	spin_unlock(&file->dirtylist_lock);

	spin_unlock(&pgc->lock);
	return;
}

/*
 * make one lego pgcache line clean, flush on dirty
 * should be call on eviction
 */
void make_lego_pgcache_clean(struct lego_pgcache_struct *pgc)
{
	struct lego_pgcache_file *file;

	spin_lock(&pgc->lock);
	if (!pgc->dirty) {
		spin_unlock(&pgc->lock);
		return;
	}

	file = find_lego_pgcache_file(pgc->filepath);
	BUG_ON(!file);

	spin_lock(&file->dirtylist_lock);

	/* check again */
	if (!pgc->dirty) {
		spin_unlock(&file->dirtylist_lock);
		return;
	}
	pgc->dirty = false;
	list_del_init(&pgc->dirtylist);
	spin_unlock(&file->dirtylist_lock);

	flush_one_cacheline_locked(pgc);

	spin_unlock(&pgc->lock);
	return;
}

int pgcache_flush_file(struct lego_pgcache_file *file)
{
	struct lego_pgcache_struct *pos;

	spin_lock(&file->dirtylist_lock);
	while(!list_empty(&file->head)) {
		pos = list_entry(file->head.next,
				struct lego_pgcache_struct, dirtylist);
		pos->dirty = false;
		list_del_init(&pos->dirtylist);
		spin_unlock(&file->dirtylist_lock);

		pgcache_debug("pgc: %p, head: %p, pgc->next: %p, sid: %u",		\
			pos, &file->head, pos->dirtylist.next, pos->storage_node);

		flush_one_cacheline_locked(pos);

		spin_lock(&file->dirtylist_lock);
	}
	spin_unlock(&file->dirtylist_lock);

	return 0;
}

struct p2m_fsync_reply {
	long		retval;
};

int handle_p2m_fsync(char *payload, struct common_header *hdr, struct thpool_buffer *tb)
{
	char *filepath = payload;
	struct p2m_fsync_reply *retbuf;
	struct lego_pgcache_file *file;

	pgcache_debug("filepath: %s", filepath);

	retbuf = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*retbuf));
	file = find_lego_pgcache_file(filepath);

	/* not accessed yet */
	if (!file) {
		retbuf->retval = 0;
		goto out;
	}

	retbuf->retval = pgcache_flush_file(file);
out:
	return retbuf->retval;
}
