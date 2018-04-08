/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <memory/pgcache.h>

struct lego_pgcache_struct *__alloc_pgcache(char *filepath, loff_t pos,
		unsigned int storage_node)
{
	struct lego_pgcache_struct *pgc;

	pgc = kmalloc(sizeof(struct lego_pgcache_struct), GFP_KERNEL);
	if (unlikely(!pgc)) {
		return ERR_PTR(-ENOMEM);
	}

	strcpy(pgc->filepath, filepath);
	pgc->pos = aligned_pos(pos);
	pgc->storage_node = storage_node;

	/* mark new allocated pgcache as empty */
	pgc->real_len = 0;
	pgc->dirty = false;

	INIT_LIST_HEAD(&pgc->dirtylist);
	INIT_LIST_HEAD(&pgc->stack_s);
	INIT_LIST_HEAD(&pgc->stack_q);

	/* init pgc lock */
	spin_lock_init(&pgc->lock);

	pgc->cached_pages = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
			PGCACHE_PREFETCH_ORDER);

	pgcache_debug("pgc:%p, pos:%Ld, pages:%p, filepath: %s",		\
			pgc, pgc->pos, pgc->cached_pages, pgc->filepath);

	return pgc;
}

void __free_pgcache_locked(struct lego_pgcache_struct *pgc)
{
	free_pages((unsigned long)pgc->cached_pages, PGCACHE_PREFETCH_ORDER);
	pgc->cached_pages = NULL;
	//kfree(pgc);
}

void __free_pgcache_struct(struct lego_pgcache_struct *pgc)
{
	free_pages((unsigned long)pgc->cached_pages, PGCACHE_PREFETCH_ORDER);
	kfree(pgc);
}
