/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _GPM_HANDLER_H
#define _GPM_HANDLER_H

#define MAX_RXBUF_SIZE   (PAGE_SIZE * 20)

#ifdef CONFIG_GPM

void gpm_handler_init(void);
void report_proc_exit(int ret_val);

#else

static inline void gpm_handler_init(void) {}
static inline void report_proc_exit(int ret_val) {}

#endif

#endif /* _GPM_HANDLER_H */
