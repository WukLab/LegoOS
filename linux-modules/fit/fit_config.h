/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LINUX_MODULE_FIT_CONFIG_H_
#define _LINUX_MODULE_FIT_CONFIG_H_

/* FIT module state */
#define FIT_MODULE_DOWN			0
#define FIT_MODULE_UP			1

/* Lego cluster config */
#define CONFIG_FIT_LOCAL_ID		2
#define CONFIG_FIT_NR_NODES		3
#define MAX_NODE			CONFIG_FIT_NR_NODES

/*
 * These configruations must match the numbers in P and M
 * Otherwise we will fail to connect.
 */
#define CONFIG_FIT_FIRST_QPN		(80)
#define CONFIG_FIT_NR_QPS_PER_PAIR	(12)

//#define CONFIG_SOCKET_O_IB

#endif /* _LINUX_MODULE_FIT_CONFIG_H_ */
