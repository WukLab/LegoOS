/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_UAPI_SYSINFO_H_
#define _LEGO_UAPI_SYSINFO_H_

#include <lego/types.h>

struct sysinfo {
	long uptime;			/* Seconds since boot */
	unsigned long loads[3];		/* 1, 5, and 15 minute load averages */
	unsigned long totalram;		/* Total usable main memory size */
	unsigned long freeram;		/* Available memory size */
	unsigned long sharedram;	/* Amount of shared memory */
	unsigned long bufferram;	/* Memory used by buffers */
	unsigned long totalswap;	/* Total swap space size */
	unsigned long freeswap;		/* swap space still available */
	__u16 procs;		   	/* Number of current processes */
	__u16 pad;		   	/* Explicit padding for m68k */
	unsigned long totalhigh;	/* Total high memory size */
	unsigned long freehigh;		/* Available high memory size */
	__u32 mem_unit;			/* Memory unit size in bytes */
	char _f[20-2*sizeof(unsigned long)-sizeof(__u32)];	/* Padding: libc5 uses this.. */
};

#endif /* _LEGO_UAPI_SYSINFO_H_ */
