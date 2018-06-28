/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RANGE_H_
#define _LEGO_RANGE_H_

struct range {
	u64   start;
	u64   end;
};

#define MAX_RESOURCE ((resource_size_t)~0)

#endif /* _LEGO_RANGE_H_ */
