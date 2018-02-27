/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This is the feature I want the most in Lego.
 * Check if any locks are still held during thread exit.
 */

#ifndef _LEGO_DEBUG_LOCKS_H_
#define _LEGO_DEBUG_LOCKS_H_

#ifdef CONFIG_LOCKDEP
void debug_check_no_locks_held(void);
#else
static inline void
debug_check_no_locks_held(void)
{
}
#endif

#endif /* _LEGO_DEBUG_LOCKS_H_ */
