/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_REPLICATION_H_
#define _LEGO_PROCESSOR_REPLICATION_H_

#ifdef CONFIG_REPLICATION_MEMORY
void replicate(pid_t tgid, unsigned long user_va,
	       unsigned int m_nid, unsigned int rep_nid, void *cache_addr);
#else
static inline void replicate(pid_t tgid, unsigned long user_va,
	       unsigned int m_nid, unsigned int rep_nid, void *cache_addr) { }
#endif

#endif /* _LEGO_PROCESSOR_REPLICATION_H_ */
