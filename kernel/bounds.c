/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Generate definitions needed by the preprocessor.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <lego/kbuild.h>

/* Include headers that define the enum constants of interest */
#include <lego/mm_zone.h>

void wuklabisawesome(void)
{
	/* The enum constants to put into include/generated/bounds.h */
	DEFINE(MAX_NR_ZONES, __MAX_NR_ZONES);
}
