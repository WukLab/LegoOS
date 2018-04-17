/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _GMM_HANDLER_H
#define _GMM_HANDLER_H

#ifdef CONFIG_GMM
#include <monitor/common.h>

/* 
 * M2MM_STATUS_REPORT
 */
int handle_m2mm_status_report(u64, struct common_header *, void *);

#endif /* CONFIG_GMM */

#endif /* _GMM_HANDLER_H */
