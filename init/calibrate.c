/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/delay.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>

unsigned long lpj_fine;

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);

void __init calibrate_delay(void)
{
	unsigned long lpj;

	if (lpj_fine) {
		lpj = lpj_fine;
		pr_info("Calibrating delay loop (skipped), "
			"value calculated using timer frequency.. \n");
	} else {
		pr_warn("We do not have any real calibration code\n");
	}

	pr_info("%lu.%02lu BogoMIPS (lpj=%lu)\n",
		lpj/(500000/HZ),
		(lpj/(5000/HZ)) % 100, lpj);

	loops_per_jiffy = lpj;
}
