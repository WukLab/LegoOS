/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/bcd.h>
#include <lego/time.h>
#include <lego/spinlock.h>
#include <lego/resource.h>
#include <lego/clocksource.h>
#include <lego/timekeeping.h>

#include <asm/io.h>
#include <asm/processor.h>
#include <asm/mc146818rtc.h>

/* For two digit years assume time is always after that */
#define CMOS_YEARS_OFFS 2000

static DEFINE_SPINLOCK(rtc_lock);

void read_persistent_clock(struct timespec *now)
{
	unsigned int status, year, mon, day, hour, min, sec;
	unsigned long flags;

	spin_lock_irqsave(&rtc_lock, flags);

	/*
	 * If UIP is clear, then we have >= 244 microseconds before
	 * RTC registers will be updated.  Spec sheet says that this
	 * is the reliable way to read RTC - registers. If UIP is set
	 * then the register access might be invalid.
	 */
	while ((CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP))
		cpu_relax();

	sec = CMOS_READ(RTC_SECONDS);
	min = CMOS_READ(RTC_MINUTES);
	hour = CMOS_READ(RTC_HOURS);
	day = CMOS_READ(RTC_DAY_OF_MONTH);
	mon = CMOS_READ(RTC_MONTH);
	year = CMOS_READ(RTC_YEAR);

	status = CMOS_READ(RTC_CONTROL);
	WARN_ON_ONCE(RTC_ALWAYS_BCD && (status & RTC_DM_BINARY));

	spin_unlock_irqrestore(&rtc_lock, flags);

	if (RTC_ALWAYS_BCD || !(status & RTC_DM_BINARY)) {
		sec = bcd2bin(sec);
		min = bcd2bin(min);
		hour = bcd2bin(hour);
		day = bcd2bin(day);
		mon = bcd2bin(mon);
		year = bcd2bin(year);
	}
	year += CMOS_YEARS_OFFS;

	now->tv_sec = mktime(year, mon, day, hour, min, sec);
	now->tv_nsec = 0;
}

/* Routines for accessing the CMOS RAM/RTC. */
unsigned char rtc_cmos_read(unsigned char addr)
{
	unsigned char val;

	outb(addr, RTC_PORT(0));
	val = inb(RTC_PORT(1));

	return val;
}

void rtc_cmos_write(unsigned char val, unsigned char addr)
{
	outb(addr, RTC_PORT(0));
	outb(val, RTC_PORT(1));
}
