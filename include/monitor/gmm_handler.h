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
void __init gmm_init(void);
#else
static inline void gmm_init(void) { }
#endif

#endif /* _GMM_HANDLER_H */
