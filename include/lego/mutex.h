/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MUTEX_H_
#define _LEGO_MUTEX_H_

/* TODO */

struct mutex {
	int x;
};

#define DEFINE_MUTEX(name) struct mutex name

#define mutex_init(name)

static __always_inline void mutex_lock(struct mutex *m)
{
}

static __always_inline void mutex_unlock(struct mutex *m)
{
}

#endif /* _LEGO_MUTEX_H_ */
