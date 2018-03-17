/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_NET_H_
#define _LEGO_NET_H_

#include <processor/fs.h>
#include <lego/kernel.h>

void init_lwip(void);

#define TOTAL_PHYS_NODE 20
#define MAX_NODE	CONFIG_FIT_NR_NODES

/*
 * Socket SYSCALL Hook
 */
#ifdef CONFIG_SOCKET_SYSCALL
void init_socket(void);
void test_socket(void);
int socket_file_open(struct file *filp);
#else
static inline void init_socket(void) { }
static inline void test_socket(void) { }

static inline int socket_file_open(struct file *filp)
{
	return -ENODEV;
}
#endif /* CONFIG_SOCKET_SYSCALL */

#ifdef CONFIG_INFINIBAND
extern struct completion ib_init_done;
extern int mad_got_one;

int ib_mad_init(void);
int ib_cache_setup(void);
int ib_cm_init(void);
int lego_ib_init(void *unused);
int lego_ib_cleanup(void);
#else
static inline int ib_mad_init(void) { return 0; }
static inline int ib_cache_setup(void) { return 0; }
static inline int ib_cm_init(void) { return 0; }
static inline int lego_ib_init(void *unused) { return 0; }
static inline int lego_ib_cleanup(void) { return 0; }
#endif /* CONFIG_INFINIBAND */

#endif /* _LEGO_NET_H_ */
