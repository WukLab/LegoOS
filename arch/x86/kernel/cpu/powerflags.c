/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Strings for the various x86 power flags
 *
 * This file must not contain any executable code.
 */

#include <asm/processor-features-flags.h>

const char *const x86_power_flags[32] = {
	"ts",	/* temperature sensor */
	"fid",  /* frequency id control */
	"vid",  /* voltage id control */
	"ttp",  /* thermal trip */
	"tm",	/* hardware thermal control */
	"stc",	/* software thermal control */
	"100mhzsteps", /* 100 MHz multiplier control */
	"hwpstate", /* hardware P-state control */
	"",	/* tsc invariant mapped to constant_tsc */
	"cpb",  /* core performance boost */
	"eff_freq_ro", /* Readonly aperf/mperf */
	"proc_feedback", /* processor feedback interface */
	"acc_power", /* accumulated power mechanism */
};

