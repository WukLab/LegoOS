/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/mmap.h>
#include <lego/ptrace.h>
#include <lego/strace.h>
#include <lego/sched.h>
#include <lego/syscalls.h>
#include <lego/waitpid.h>
#include <lego/files.h>
#include <lego/sched.h>
#include <processor/fs.h>
#include <generated/asm-offsets.h>
#include <generated/unistd_64.h>

#include "internal.h"

void strace_printflags(struct strace_flag *sf, unsigned long flags, unsigned char *buf)
{
	int n = 0;
	int offset;

	if (WARN_ON(!sf || !buf))
		return;

	for (; (flags || !n) && sf->str; ++sf) {
		if ((flags == sf->val) ||
		    (sf->val && (flags & sf->val) == sf->val)) {
			offset = sprintf(buf, "%s%s", (n++ ? "|" : ""), sf->str);
			buf += offset;

			flags &= ~sf->val;
		}
		if (!flags)
			break;
	}
}
