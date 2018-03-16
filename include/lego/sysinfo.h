/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * lego_sysinfo is used to report the per-manager resource usage
 * This is different from `struct sysinfo`, which is used by sysinfo syscall.
 * That one should report the free memory info within user's subscription.
 */

#ifndef _LEGO_SYSINFO_H_
#define _LEGO_SYSINFO_H_

#include <lego/types.h>

struct manager_sysinfo {
	long uptime;			/* Seconds since boot */
	unsigned long loads[3];		/* 1, 5, and 15 minute load averages */
	unsigned long totalram;		/* Total usable main memory size */
	unsigned long freeram;		/* Available memory size */
	__u16 procs;		   	/* Number of current processes */
	__u32 mem_unit;			/* Memory unit size in bytes */
};

void manager_meminfo(struct manager_sysinfo *val);

#endif /* _LEGO_SYSINFO_H_ */
