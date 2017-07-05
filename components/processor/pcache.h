/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _COMPONENT_PROCESSOR_PCACHE_H_
#define _COMPONENT_PROCESSOR_PCACHE_H_

/* Cacheline metadata bits layout: */
#define _PCACHE_BIT_VALID	0
#define _PCACHE_BIT_DIRTY	1
#define _PCACHE_BIT_ACCESSED	2
#define _PCACHE_BIT_NX		3

#define _PCACHE_VALID		(_AT(unsigned long, 1) << _PCACHE_BIT_VALID)
#define _PCACHE_DIRTY		(_AT(unsigned long, 1) << _PCACHE_BIT_DIRTY)
#define _PCACHE_ACCESSED	(_AT(unsigned long, 1) << _PCACHE_BIT_ACCESSED)
#define _PCACHE_NX		(_AT(unsigned long, 1) << _PCACHE_BIT_NX)

static inline int __pcache_valid(unsigned long meta)
{
	return meta & _PCACHE_VALID;
}

static inline int __pcache_dirty(unsigned long meta)
{
	return meta & _PCACHE_DIRTY;
}

static inline int __pcache_accessed(unsigned long meta)
{
	return meta & _PCACHE_ACCESSED;
}

static inline int __pcache_nx(unsigned long meta)
{
	return meta & _PCACHE_NX;
}

#define pcache_valid(meta)	__pcache_valid(*(unsigned long *)meta)
#define pcache_dirty(meta)	__pcache_dirty(*(unsigned long *)meta)
#define pcache_accessed(meta)	__pcache_accessed(*(unsigned long *)meta)
#define pcache_nx(meta)		__pcache_nx(*(unsigned long *)meta)

#endif /* _COMPONENT_PROCESSOR_PCACHE_H_ */
