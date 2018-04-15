/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_VNODE_TYPES_H_
#define _LEGO_PROCESSOR_VNODE_TYPES_H_

#include <lego/types.h>

struct vnode_struct {
	int			p_nid;
	int			vid;
	int			ip;
	struct hlist_node	node;
} __attribute__((packed)) __attribute__((aligned(64)));

#endif /* _LEGO_PROCESSOR_VNODE_TYPES_H_ */
