/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/hashtable.h>
#include <lego/spinlock.h>
#include <lego/comp_memory.h>
#include <memory/pgcache.h>

/* lock to protect pgcache hashtable struct */
static DEFINE_SPINLOCK(pgcache_hash_lock);
static DEFINE_HASHTABLE(pgcache_hash, PGCACHE_HASH_BITS);
static unsigned int lookups = 0;
static unsigned int walks = 0;

static unsigned int BKDRHash(char *str)
{
	unsigned int seed = 131;
	unsigned int hash = 0;

	while (*str) {
		hash = hash*seed + (*str++);
	}

	return hash & 0x7fffffff;
}

/*
 * TODO: replace with correct key function
 * DONE
 */
static unsigned int get_key(char *filename, loff_t _aligned_pos)
{
	unsigned int key = 0;

	key = BKDRHash(filename);
	key += (_aligned_pos) >> (PAGE_SHIFT + PGCACHE_PREFETCH_ORDER);

	return key;
}

/*
 * when this func is invoked, the caller is responsible to do sanity
 * check if pgc is already exist, we avoid reductant check here
 * for performance reasons
 */
int ht_insert_lego_pgcache_struct(struct lego_pgcache_struct *pgc)
{
	unsigned int key;

	BUG_ON(!pgc || strlen(pgc->filepath) == 0);

	pgcache_debug("pgc:%p, pos:%Ld, pages:%p, filepath: %s",		\
			pgc, pgc->pos, pgc->cached_pages, pgc->filepath);

	key = get_key(pgc->filepath, pgc->pos);

	spin_lock(&pgcache_hash_lock);
	hash_add(pgcache_hash, &pgc->link, key);
	spin_unlock(&pgcache_hash_lock);

	return 0;
}

void ht_remove_lego_pgcache_struct(struct lego_pgcache_struct *pgc)
{
	BUG_ON(!pgc || strlen(pgc->filepath) == 0);
	spin_lock(&pgcache_hash_lock);
	hash_del(&pgc->link);
	spin_unlock(&pgcache_hash_lock);
}

void free_lego_pgcache_struct(struct lego_pgcache_struct *pgc)
{
	struct lego_pgcache_struct *p;
	unsigned int key;

	BUG_ON(!pgc || strlen(pgc->filepath) == 0);

	key = get_key(pgc->filepath, pgc->pos);

	spin_lock(&pgcache_hash_lock);
	hash_for_each_possible(pgcache_hash, p, link, key) {
		if (likely(p->pos == pgc->pos &&
			strcmp(p->filepath, pgc->filepath) == 0)) {
			hash_del(&p->link);
			spin_unlock(&pgcache_hash_lock);
			/* TODO:
			 * finish implementing __free_pgcache
			 */
			__free_pgcache_struct(p);
			return;
		}
	}
	spin_unlock(&pgcache_hash_lock);
	WARN(1, "Fail to find pgc->(filepath:%s,pos:%Ld)\n", pgc->filepath, pgc->pos);
	return;
}

struct lego_pgcache_struct *
	find_lego_pgcache_struct(char *filepath, loff_t pos)
{
	loff_t _aligned_pos;
	struct lego_pgcache_struct *pgc;
	unsigned int key;

	if (unlikely(strlen(filepath) == 0))
		return NULL;

	_aligned_pos = aligned_pos(pos);
	key = get_key(filepath, _aligned_pos);

	spin_lock(&pgcache_hash_lock);
	lookups++;
	hash_for_each_possible(pgcache_hash, pgc, link, key) {
		walks++;
		if (likely(pgc->pos == _aligned_pos &&
			strcmp(pgc->filepath, filepath) == 0)) {
			spin_unlock(&pgcache_hash_lock);

			pgcache_debug("pgc:%p, pos:%Ld, pages:%p, filepath: %s",		\
				pgc, pgc->pos, pgc->cached_pages, pgc->filepath);

			return pgc;
		}
	}
	spin_unlock(&pgcache_hash_lock);

	return NULL;
}

int drop_pgcache(void)
{
	int bkt;
	struct lego_pgcache_struct *pgc;
	struct hlist_node *tmp;

	spin_lock(&pgcache_hash_lock);
	pr_info("lookups = %u, walks = %u\n", lookups, walks);
	hash_for_each_safe(pgcache_hash, bkt, tmp, pgc, link) {
		hash_del(&pgc->link);

		/*
		 * free lines one by one
		 */
		__free_pgcache_struct(pgc);
	}
	lookups = 0;
	walks = 0;
	spin_unlock(&pgcache_hash_lock);

	if (likely(hash_empty(pgcache_hash))) {
		pr_info("Successfully drop lego pgcache.\n");
	} else {
		pr_warn("Lego pgcache is not dropped entirely");
	}
	return 0;
}
