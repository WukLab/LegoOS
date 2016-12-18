/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PAGE_FLAGS_H_
#define _LEGO_PAGE_FLAGS_H_

#ifndef __GENERATING_BOUNDS_H
#include <generated/bounds.h>
#endif

#include <lego/types.h>
#include <lego/bitops.h>

/*
 * page->flags bits:
 *
 */
enum pageflags {
	PG_locked,
	PG_referenced,
	PG_dirty,
	PG_reserved,
	PG_private,

	__NR_PAGEFLAGS,
};

#ifndef __GENERATING_BOUNDS_H
struct page;

#define TEST_PAGE_FLAG(uname, lname)				\
static inline int Page##uname(const struct page *page)		\
{								\
	return test_bit(PG_##lname, &page->flags);		\
}

#define SET_PAGE_FLAG(uname, lname)				\
static inline void SetPage##uname(struct page *page)		\
{								\
	set_bit(PG_##lname, &page->flags);			\
}

#define CLEAR_PAGE_FLAG(uname, lname)				\
static inline void ClearPage##uname(struct page *page)		\
{								\
	clear_bit(PG_##lname, &page->flags);			\
}

#define __SET_PAGE_FLAG(uname, lname)				\
static inline void __SetPage##uname(struct page *page)		\
{								\
	__set_bit(PG_##lname, &page->flags);			\
}

#define __CLEAR_PAGE_FLAG(uname, lname)				\
static inline void __ClearPage##uname(struct page *page)	\
{								\
	__clear_bit(PG_##lname, &page->flags);			\
}

#define TEST_SET_FLAG(uname, lname)				\
static inline int TestSetPage##uname(struct page *page)		\
{								\
	return test_and_set_bit(PG_##lname, &page->flags);	\
}

#define TEST_CLEAR_FLAG(uname, lname)				\
static inline int TestClearPage##uname(struct page *page)	\
{								\
	return test_and_clear_bit(PG_##lname, &page->flags);	\
}

#define __TEST_SET_FLAG(uname, lname)				\
static inline int __TestSetPage##uname(struct page *page)	\
{								\
	return __test_and_set_bit(PG_##lname, &page->flags);	\
}

#define __TEST_CLEAR_FLAG(uname, lname)				\
static inline int __TestClearPage##uname(struct page *page)	\
{								\
	return __test_and_clear_bit(PG_##lname, &page->flags);	\
}

#define PAGE_FLAG(uname, lname)					\
	TEST_PAGE_FLAG(uname, lname)				\
	SET_PAGE_FLAG(uname, lname)				\
	CLEAR_PAGE_FLAG(uname, lname)				\
	__SET_PAGE_FLAG(uname, lname)				\
	__CLEAR_PAGE_FLAG(uname, lname)				\
	TEST_SET_FLAG(uname, lname)				\
	TEST_CLEAR_FLAG(uname, lname)				\
	__TEST_SET_FLAG(uname, lname)				\
	__TEST_CLEAR_FLAG(uname, lname)

PAGE_FLAG(Locked, locked)
PAGE_FLAG(Referenced, referenced)
PAGE_FLAG(Dirty, dirty)
PAGE_FLAG(Reserved, reserved)
PAGE_FLAG(Private, private)

/*
 * For pages that are never mapped to userspace, page->mapcount may be
 * used for storing extra information about page type. Any value used
 * for this purpose must be <= -2, but it's better start not too close
 * to -2 so that an underflow of the page_mapcount() won't be mistaken
 * for a special page.
 */
#define PAGE_MAPCOUNT_OPS(uname, lname)					\
static __always_inline int Page##uname(struct page *page)		\
{									\
	return atomic_read(&page->_mapcount) ==				\
				PAGE_##lname##_MAPCOUNT_VALUE;		\
}									\
static __always_inline void __SetPage##uname(struct page *page)		\
{									\
	VM_BUG_ON_PAGE(atomic_read(&page->_mapcount) != -1, page);	\
	atomic_set(&page->_mapcount, PAGE_##lname##_MAPCOUNT_VALUE);	\
}									\
static __always_inline void __ClearPage##uname(struct page *page)	\
{									\
	VM_BUG_ON_PAGE(!Page##uname(page), page);			\
	atomic_set(&page->_mapcount, -1);				\
}

/*
 * PageBuddy() indicate that the page is free and in the buddy system
 * (see mm/page_alloc.c).
 */
#define PAGE_BUDDY_MAPCOUNT_VALUE		(-128)
PAGE_MAPCOUNT_OPS(Buddy, BUDDY)

#endif /* __GENERATING_BOUNDS_H */
#endif /* _LEGO_PAGE_FLAGS_H_ */
