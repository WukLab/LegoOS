/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/tracepoint.h>

#define __def_pageflag_names					\
	{1UL << PG_locked,		"locked"	},	\
	{1UL << PG_referenced,		"referenced"	},	\
	{1UL << PG_dirty,		"dirty"		},	\
	{1UL << PG_lru,			"lru"		},	\
	{1UL << PG_active,		"active"	},	\
	{1UL << PG_reserved,		"reserved"	},	\
	{1UL << PG_private,		"private"	},	\
	{1UL << PG_unevictable,		"unevictable"	},	\
	{1UL << PG_slab,		"slab"		},	\
	{1UL << PG_slob_free,		"slob_free"	}

const struct trace_print_flags pageflag_names[] = {
	__def_pageflag_names,
	{0, NULL}
};

void dump_page(struct page *page, const char *reason)
{
	pr_emerg("page:%p count:%d mapcount:%d\n",
		  page, page_ref_count(page), atomic_read(&page->_mapcount));

	BUILD_BUG_ON(ARRAY_SIZE(pageflag_names) != __NR_PAGEFLAGS + 1);

	pr_emerg("flags: %#lx(%pGp)\n", page->flags, &page->flags);

	if (reason)
		pr_alert("page dumped because: %s\n", reason);
}
