/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _GPM_HANDLER
#define _GPM_HANDLER

#include <monitor/common.h>

int gpm_handler(void *);
void report_proc_exit(int ret_val);

#endif /* _GPM_HANDLER */
