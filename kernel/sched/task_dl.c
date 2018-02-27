/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include <lego/sched.h>
#include "sched.h"

void init_dl_rq(struct dl_rq *dl_rq)
{

}

const struct sched_class dl_sched_class = {
	.next			= &rt_sched_class,
};
