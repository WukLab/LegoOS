/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/time.h>
#include <lego/kernel.h>

#include <asm/hpet.h>
#include <asm/apic.h>

int hpet_enable(void)
{
	return 1;
}
