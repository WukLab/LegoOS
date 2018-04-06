/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/bug.h>
#include <lego/kernel.h>
#include <lego/profile.h>

void boot_time_profile(void)
{
	/* smp must be initalized first */
	WARN_ON(system_state != SYSTEM_RUNNING);

	profile_tlb_shootdown();
}
