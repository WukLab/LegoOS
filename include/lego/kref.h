/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_KREF_H_
#define _LEGO_KREF_H_

#include <lego/atomic.h>

struct kref {
	atomic_t refcount;
};

#endif /* _LEGO_KREF_H_ */
