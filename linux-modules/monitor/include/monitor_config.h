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

/* 
 * IB configuration 
 * USE_IBAPI: disable ibapi send reply
 * MAX_RXBUF_SIZE: receive buffer size
 * LEGO_LOCAL_NID: local node id
 */
#define USE_IBAPI 			1
#define MAX_RXBUF_SIZE			(PAGE_SIZE * 20)
#define LEGO_LOCAL_NID			CONFIG_FIT_LOCAL_ID

/* 
 * GPM configuration 
 * IP_ADDRESS_BASE: start point of ip address, represented in integer, 
 * 		    same as "10.0.0.0"
 * VNODE_MAP_ORDER: vnode map order, should be consistent with processor's config
 * PROCESSOR_NODE_COUNT: number of processor node connected
 * pnode_nids: process node id array with size PROCESSOR_NODE_COUNT
 */
#define IP_ADDRESS_BASE			0x0A000000
#define VNODE_MAP_ORDER			8
#define PROCESSOR_NODE_COUNT 		2
const static int pnode_nids[PROCESSOR_NODE_COUNT] =
{
	0,
	1,
};

/* 
 * GMM configuration
 * CONFIG_MEM_NR_NODES: save as aboce, just for compatibility with Lego def
 * MNODES_STATUS_REQUEST: enable memory node status polling
 * MNODES_STATUS_REQUEST_PERIOD: memory nodes status polling period
 * ROUND_ROBIN_CHOOSE: policy for choosing memory node
 * MEMORY_NODE_COUNT: number of memory nodes connected
 * mnode_nids: memory node id array with size MEMORY_NODE_COUNT
 */
#define CONFIG_MEM_NR_NODES		MEMORY_NODE_COUNT
#define MNODES_STATUS_REQUEST		0
#define MNODES_STATUS_REQUEST_PERIOD	10
#define ROUND_ROBIN_CHOOSE		1
#define MEMORY_NODE_COUNT 		1
const static int mnode_nids[MEMORY_NODE_COUNT] =
{
	2,
};

#endif /* _LEGO_MONITOR_CONFIG_H */
