/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _KERNEL_TIME_INTERNAL_H_
#define _KERNEL_TIME_INTERNAL_H_

u64 ntp_tick_length(void);
int second_overflow(time_t secs);
int __weak update_persistent_clock(struct timespec now);
int ntp_validate_timex(struct timex *txc);
ktime_t ntp_get_next_leap(void);
void ntp_clear(void);
void __init ntp_init(void);

#endif /* _KERNEL_TIME_INTERNAL_H_ */
