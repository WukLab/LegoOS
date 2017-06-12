/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Real-Time Scheduling Class
 * Mapped to SCHED_FIFO and SCHED_RR policies
 */

#include <lego/sched.h>
#include "sched.h"


const struct sched_class rt_sched_class = {
	.next			= &fair_sched_class,
};
