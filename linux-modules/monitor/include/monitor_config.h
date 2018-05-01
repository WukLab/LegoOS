/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
/*
 * Configurations for all monitor modules
 */

#ifndef _LEGO_MONITOR_CONFIG_H
#define _LEGO_MONITOR_CONFIG_H

#include "../../fit/fit_config.h"

/*
 * IB configuration
 * USE_IBAPI: disable ibapi send reply
 * MAX_RXBUF_SIZE: receive buffer size
 * LEGO_LOCAL_NID: local node id
 */
#define USE_IBAPI			1
#define MAX_RXBUF_SIZE			(PAGE_SIZE * 20)
#define LEGO_LOCAL_NID			CONFIG_FIT_LOCAL_ID

/*
 * GPM configuration
 * IP_ADDRESS_BASE:			start point of ip address, represented in integer,
 *					same as "10.0.0.0"
 * VNODE_MAP_ORDER:			vnode map order, should be consistent with processor's config
 * PROCESSOR_NODE_COUNT:		number of processor node connected
 * pnode_nids:				process node id array with size PROCESSOR_NODE_COUNT
 */
#define IP_ADDRESS_BASE			0x0A000000
#define VNODE_MAP_ORDER			8
#define PROCESSOR_NODE_COUNT		1
const static int pnode_nids[PROCESSOR_NODE_COUNT] =
{
	0,
};

/*
 * GMM configuration
 * CONFIG_MEM_NR_NODES:			save as aboce, just for compatibility with Lego def
 * MEMORY_NODE_COUNT:			number of memory nodes connected
 *
 * momery node selection policy(only enable 1):
 * RR_CHOOSE_INTERVAL:			round robin interval, if 1, xyxy, if 2, xxyy, etc.
 * PURE_RR_CHOOSE:			pure round robin
 * NETWORK_TRAFFIC_RR_CHOOSE:		similar to RR, but switch depends on network traffic
 * RESIDENT_MEMORY_CHOOSE:		choose depends on maximum free resident memory
 *
 * mnode_nids:				memory node id array with size MEMORY_NODE_COUNT
 */
#define MEMORY_NODE_COUNT		1
#define CONFIG_MEM_NR_NODES		CONFIG_FIT_NR_NODES
#define RR_CHOOSE_INTERVAL		4
#define PURE_RR_CHOOSE			0
#define NETWORK_TRAFFIC_RR_CHOOSE	1
#define RESIDENT_MEMORY_CHOOSE		0
const static int mnode_nids[MEMORY_NODE_COUNT] =
{
	1,
};

#endif /* _LEGO_MONITOR_CONFIG_H */
