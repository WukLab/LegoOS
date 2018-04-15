/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_VNODE_H_
#define _LEGO_PROCESSOR_VNODE_H_

#include <lego/hashtable.h>
#include <lego/spinlock.h>
#include <lego/comp_common.h>
#include <processor/vnode_types.h>
#include <monitor/common.h>

#ifdef CONFIG_VNODE

inline bool vnode_exist(int vid);

struct vnode_struct *ip_find_vnode(int ip);
inline struct vnode_struct *vid_find_vnode(int vid);

int p2pm_request_vnode(void);
void handle_pm2p_broadcast_vnode(struct pm2p_broadcast_vnode_struct *vnode, u64 desc);

#else
static inline bool vnode_exist(int vid) { return false; }
static inline struct vnode_struct *ip_find_vnode(int ip) { return NULL; }
static inline struct vnode_struct *vid_find_vnode(int vid) { return NULL; }
static inline int p2pm_request_vnode(void) { return -EPERM; }
static inline void 
handle_pm2p_broadcast_vnode(struct pm2p_broadcast_vnode_struct *vnode, u64 desc) {} 
#endif /* CONFIG_VNODE */

#endif /* _LEGO_PROCESSOR_VNODE_H_ */
