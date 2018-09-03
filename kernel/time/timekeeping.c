/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/timex.h>
#include <lego/ktime.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>
#include <lego/seqlock.h>
#include <lego/timekeeping.h>
#include <lego/clocksource.h>

#include "internal.h"

#define TK_CLEAR_NTP		(1 << 0)
#define TK_MIRROR		(1 << 1)
#define TK_CLOCK_WAS_SET	(1 << 2)

/*
 * The most important data for readout fits into a single 64 byte
 * cache line.
 */
static struct {
	seqcount_t		seq;
	struct timekeeper	timekeeper;
} tk_core ____cacheline_aligned;

static DEFINE_SPINLOCK(timekeeper_lock);
static struct timekeeper shadow_timekeeper;

/* Flag for if there is a persistent clock on this platform */
static bool persistent_clock_exists;

static inline void tk_normalize_xtime(struct timekeeper *tk)
{
	while (tk->tkr_mono.xtime_nsec >= ((u64)NSEC_PER_SEC << tk->tkr_mono.shift)) {
		tk->tkr_mono.xtime_nsec -= (u64)NSEC_PER_SEC << tk->tkr_mono.shift;
		tk->xtime_sec++;
	}
}

static inline struct timespec tk_xtime(struct timekeeper *tk)
{
	struct timespec ts;

	ts.tv_sec = tk->xtime_sec;
	ts.tv_nsec = (long)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);
	return ts;
}

static void tk_set_xtime(struct timekeeper *tk, const struct timespec *ts)
{
	tk->xtime_sec = ts->tv_sec;
	tk->tkr_mono.xtime_nsec = (u64)ts->tv_nsec << tk->tkr_mono.shift;
}

static inline cycle_t clocksource_delta(cycle_t now, cycle_t last, cycle_t mask)
{
	cycle_t ret = (now - last) & mask;

	/*
	 * Prevent time going backwards by checking the MSB of mask in
	 * the result. If set, return 0.
	 */
	return ret & ~(mask >> 1) ? 0 : ret;
}

/**
 * __timekeeping_set_tai_offset - Lock free worker function
 *
 */
static void __timekeeping_set_tai_offset(struct timekeeper *tk, s32 tai_offset)
{
	tk->tai_offset = tai_offset;
	tk->offs_tai = ktime_add(tk->offs_real, ktime_set(tai_offset, 0));
}

/*
 * tk_clock_read - atomic clocksource read() helper
 *
 * This helper is necessary to use in the read paths because, while the
 * seqlock ensures we don't return a bad value while structures are updated,
 * it doesn't protect from potential crashes. There is the possibility that
 * the tkr's clocksource may change between the read reference, and the
 * clock reference passed to the read function.  This can cause crashes if
 * the wrong clocksource is passed to the wrong read function.
 * This isn't necessary to use when holding the timekeeper_lock or doing
 * a read of the fast-timekeeper tkrs (which is protected by its own locking
 * and update logic).
 */
static inline u64 tk_clock_read(struct tk_read_base *tkr)
{
	struct clocksource *clock = READ_ONCE(tkr->clock);

	return clock->read(clock);
}

#ifdef CONFIG_DEBUG_TIMEKEEPING
#define WARNING_FREQ (HZ*300) /* 5 minute rate-limiting */

static void timekeeping_check_update(struct timekeeper *tk, cycle_t offset)
{

	cycle_t max_cycles = tk->tkr_mono.clock->max_cycles;
	const char *name = tk->tkr_mono.clock->name;

	if (offset > max_cycles) {
		pr_err("WARNING: timekeeping: Cycle offset (%lld) is larger than allowed by the '%s' clock's max_cycles value (%lld): time overflow danger\n",
				offset, name, max_cycles);
		pr_err("         timekeeping: Your kernel is sick, but tries to cope by capping time updates\n");
	} else {
		if (offset > (max_cycles >> 1)) {
			pr_err("INFO: timekeeping: Cycle offset (%lld) is larger than the '%s' clock's 50%% safety margin (%lld)\n",
					offset, name, max_cycles >> 1);
			pr_err("      timekeeping: Your kernel is still fine, but is feeling a bit nervous\n");
		}
	}

	if (tk->underflow_seen) {
		if (jiffies - tk->last_warning > WARNING_FREQ) {
			pr_err("WARNING: Underflow in clocksource '%s' observed, time update ignored.\n", name);
			pr_err("         Please report this, consider using a different clocksource, if possible.\n");
			pr_err("         Your kernel is probably still fine.\n");
			tk->last_warning = jiffies;
		}
		tk->underflow_seen = 0;
	}

	if (tk->overflow_seen) {
		if (jiffies - tk->last_warning > WARNING_FREQ) {
			pr_err("WARNING: Overflow in clocksource '%s' observed, time update capped.\n", name);
			pr_err("         Please report this, consider using a different clocksource, if possible.\n");
			pr_err("         Your kernel is probably still fine.\n");
			tk->last_warning = jiffies;
		}
		tk->overflow_seen = 0;
	}
}

static inline cycle_t timekeeping_get_delta(struct tk_read_base *tkr)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	cycle_t now, last, mask, max, delta;
	unsigned int seq;

	/*
	 * Since we're called holding a seqlock, the data may shift
	 * under us while we're doing the calculation. This can cause
	 * false positives, since we'd note a problem but throw the
	 * results away. So nest another seqlock here to atomically
	 * grab the points we are checking with.
	 */
	do {
		seq = read_seqcount_begin(&tk_core.seq);
		now = tk_clock_read(tkr);
		last = tkr->cycle_last;
		mask = tkr->mask;
		max = tkr->clock->max_cycles;
	} while (read_seqcount_retry(&tk_core.seq, seq));

	delta = clocksource_delta(now, last, mask);

	/*
	 * Try to catch underflows by checking if we are seeing small
	 * mask-relative negative values.
	 */
	if (unlikely((~delta & mask) < (mask >> 3))) {
		tk->underflow_seen = 1;
		delta = 0;
	}

	/* Cap delta value to the max_cycles values to avoid mult overflows */
	if (unlikely(delta > max)) {
		tk->overflow_seen = 1;
		delta = tkr->clock->max_cycles;
	}

	return delta;
}
#else
static inline void timekeeping_check_update(struct timekeeper *tk, cycle_t offset)
{
}
static inline cycle_t timekeeping_get_delta(struct tk_read_base *tkr)
{
	cycle_t cycle_now, delta;

	/* read clocksource */
	cycle_now = tk_clock_read(tkr);

	/* calculate the delta since the last update_wall_time */
	delta = clocksource_delta(cycle_now, tkr->cycle_last, tkr->mask);

	return delta;
}
#endif

/*
 * tk_update_leap_state - helper to update the next_leap_ktime
 */
static inline void tk_update_leap_state(struct timekeeper *tk)
{
	tk->next_leap_ktime = ntp_get_next_leap();
	if (tk->next_leap_ktime != KTIME_MAX)
		/* Convert to monotonic time */
		tk->next_leap_ktime = ktime_sub(tk->next_leap_ktime, tk->offs_real);
}

/*
 * Update the ktime_t based scalar nsec members of the timekeeper
 */
static inline void tk_update_ktime_data(struct timekeeper *tk)
{
	u64 seconds;
	u32 nsec;

	/*
	 * The xtime based monotonic readout is:
	 *	nsec = (xtime_sec + wtm_sec) * 1e9 + wtm_nsec + now();
	 * The ktime based monotonic readout is:
	 *	nsec = base_mono + now();
	 * ==> base_mono = (xtime_sec + wtm_sec) * 1e9 + wtm_nsec
	 */
	seconds = (u64)(tk->xtime_sec + tk->wall_to_monotonic.tv_sec);
	nsec = (u32) tk->wall_to_monotonic.tv_nsec;
	tk->tkr_mono.base = ns_to_ktime(seconds * NSEC_PER_SEC + nsec);

	/* Update the monotonic raw base */
	tk->tkr_raw.base = timespec_to_ktime(tk->raw_time);

	/*
	 * The sum of the nanoseconds portions of xtime and
	 * wall_to_monotonic can be greater/equal one second. Take
	 * this into account before updating tk->ktime_sec.
	 */
	nsec += (u32)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);
	if (nsec >= NSEC_PER_SEC)
		seconds++;
	tk->ktime_sec = seconds;
}

void update_vsyscall(struct timekeeper *tk)
{
	/* TODO vsyscall */
}

/* must hold timekeeper_lock */
static void timekeeping_update(struct timekeeper *tk, unsigned int action)
{
	if (action & TK_CLEAR_NTP) {
		tk->ntp_error = 0;
		ntp_clear();
	}

	tk_update_leap_state(tk);
	tk_update_ktime_data(tk);

	update_vsyscall(tk);

	if (action & TK_CLOCK_WAS_SET)
		tk->clock_was_set_seq++;
	/*
	 * The mirroring of the data to the shadow-timekeeper needs
	 * to happen last here to ensure we don't over-write the
	 * timekeeper structure on the next update with stale data
	 */
	if (action & TK_MIRROR)
		memcpy(&shadow_timekeeper, &tk_core.timekeeper,
		       sizeof(tk_core.timekeeper));
}

/**
 * tk_setup_internals - Set up internals to use clocksource clock.
 *
 * @tk:		The target timekeeper to setup.
 * @clock:	Pointer to clocksource.
 *
 * Calculates a fixed cycle/nsec interval for a given clocksource/adjustment
 * pair and interval request.
 *
 * Unless you're the timekeeping code, you should not be using this!
 */
static void tk_setup_internals(struct timekeeper *tk, struct clocksource *clock)
{
	u64 interval;
	u64 tmp, ntpinterval;
	struct clocksource *old_clock;

	++tk->cs_was_changed_seq;
	old_clock = tk->tkr_mono.clock;
	tk->tkr_mono.clock = clock;
	tk->tkr_mono.read = clock->read;
	tk->tkr_mono.mask = clock->mask;
	tk->tkr_mono.cycle_last = tk_clock_read(&tk->tkr_mono);

	tk->tkr_raw.clock = clock;
	tk->tkr_raw.read = clock->read;
	tk->tkr_raw.mask = clock->mask;
	tk->tkr_raw.cycle_last = tk->tkr_mono.cycle_last;

	/* Do the ns -> cycle conversion first, using original mult */
	tmp = NTP_INTERVAL_LENGTH;
	tmp <<= clock->shift;
	ntpinterval = tmp;
	tmp += clock->mult/2;
	do_div(tmp, clock->mult);
	if (tmp == 0)
		tmp = 1;

	interval = (u64) tmp;
	tk->cycle_interval = interval;

	/* Go back from cycles -> shifted ns */
	tk->xtime_interval = interval * clock->mult;
	tk->xtime_remainder = ntpinterval - tk->xtime_interval;
	tk->raw_interval = (interval * clock->mult) >> clock->shift;

	 /* if changing clocks, convert xtime_nsec shift units */
	if (old_clock) {
		int shift_change = clock->shift - old_clock->shift;
		if (shift_change < 0)
			tk->tkr_mono.xtime_nsec >>= -shift_change;
		else
			tk->tkr_mono.xtime_nsec <<= shift_change;
	}
	tk->tkr_raw.xtime_nsec = 0;

	tk->tkr_mono.shift = clock->shift;
	tk->tkr_raw.shift = clock->shift;

	tk->ntp_error = 0;
	tk->ntp_error_shift = NTP_SCALE_SHIFT - clock->shift;
	tk->ntp_tick = ntpinterval << tk->ntp_error_shift;

	/*
	 * The timekeeper keeps its own mult values for the currently
	 * active clocksource. These value will be adjusted via NTP
	 * to counteract clock drifting.
	 */
	tk->tkr_mono.mult = clock->mult;
	tk->tkr_raw.mult = clock->mult;
	tk->ntp_err_mult = 0;
}

static void tk_set_wall_to_mono(struct timekeeper *tk, struct timespec wtm)
{
	struct timespec tmp;

	/*
	 * Verify consistency of: offset_real = -wall_to_monotonic
	 * before modifying anything
	 */
	set_normalized_timespec(&tmp, -tk->wall_to_monotonic.tv_sec,
					-tk->wall_to_monotonic.tv_nsec);
	WARN_ON_ONCE(tk->offs_real != timespec_to_ktime(tmp));
	tk->wall_to_monotonic = wtm;
	set_normalized_timespec(&tmp, -wtm.tv_sec, -wtm.tv_nsec);
	tk->offs_real = timespec_to_ktime(tmp);
	tk->offs_tai = ktime_add(tk->offs_real, ktime_set(tk->tai_offset, 0));
}

/**
 * accumulate_nsecs_to_secs - Accumulates nsecs into secs
 *
 * Helper function that accumulates the nsecs greater than a second
 * from the xtime_nsec field to the xtime_secs field.
 * It also calls into the NTP code to handle leapsecond processing.
 *
 */
static inline unsigned int accumulate_nsecs_to_secs(struct timekeeper *tk)
{
	u64 nsecps = (u64)NSEC_PER_SEC << tk->tkr_mono.shift;
	unsigned int clock_set = 0;

	while (tk->tkr_mono.xtime_nsec >= nsecps) {
		int leap;

		tk->tkr_mono.xtime_nsec -= nsecps;
		tk->xtime_sec++;

		/* Figure out if its a leap sec and apply if needed */
		leap = second_overflow(tk->xtime_sec);
		if (unlikely(leap)) {
			struct timespec ts;

			tk->xtime_sec += leap;

			ts.tv_sec = leap;
			ts.tv_nsec = 0;
			tk_set_wall_to_mono(tk,
				timespec_sub(tk->wall_to_monotonic, ts));

			__timekeeping_set_tai_offset(tk, tk->tai_offset - leap);

			clock_set = TK_CLOCK_WAS_SET;
		}
	}
	return clock_set;
}

/**
 * logarithmic_accumulation - shifted accumulation of cycles
 *
 * This functions accumulates a shifted interval of cycles into
 * into a shifted interval nanoseconds. Allows for O(log) accumulation
 * loop.
 *
 * Returns the unconsumed cycles.
 */
static cycle_t logarithmic_accumulation(struct timekeeper *tk, cycle_t offset,
						u32 shift,
						unsigned int *clock_set)
{
	cycle_t interval = tk->cycle_interval << shift;
	u64 raw_nsecs;

	/* If the offset is smaller than a shifted interval, do nothing */
	if (offset < interval)
		return offset;

	/* Accumulate one shifted interval */
	offset -= interval;
	tk->tkr_mono.cycle_last += interval;
	tk->tkr_raw.cycle_last  += interval;

	tk->tkr_mono.xtime_nsec += tk->xtime_interval << shift;
	*clock_set |= accumulate_nsecs_to_secs(tk);

	/* Accumulate raw time */
	raw_nsecs = (u64)tk->raw_interval << shift;
	raw_nsecs += tk->raw_time.tv_nsec;
	if (raw_nsecs >= NSEC_PER_SEC) {
		u64 raw_secs = raw_nsecs;
		raw_nsecs = do_div(raw_secs, NSEC_PER_SEC);
		tk->raw_time.tv_sec += raw_secs;
	}
	tk->raw_time.tv_nsec = raw_nsecs;

	/* Accumulate error between NTP and clock interval */
	tk->ntp_error += tk->ntp_tick << shift;
	tk->ntp_error -= (tk->xtime_interval + tk->xtime_remainder) <<
						(tk->ntp_error_shift + shift);

	return offset;
}

/*
 * Apply a multiplier adjustment to the timekeeper
 */
static __always_inline void timekeeping_apply_adjustment(struct timekeeper *tk,
							 s64 offset,
							 bool negative,
							 int adj_scale)
{
	s64 interval = tk->cycle_interval;
	s32 mult_adj = 1;

	if (negative) {
		mult_adj = -mult_adj;
		interval = -interval;
		offset  = -offset;
	}
	mult_adj <<= adj_scale;
	interval <<= adj_scale;
	offset <<= adj_scale;

	/*
	 * So the following can be confusing.
	 *
	 * To keep things simple, lets assume mult_adj == 1 for now.
	 *
	 * When mult_adj != 1, remember that the interval and offset values
	 * have been appropriately scaled so the math is the same.
	 *
	 * The basic idea here is that we're increasing the multiplier
	 * by one, this causes the xtime_interval to be incremented by
	 * one cycle_interval. This is because:
	 *	xtime_interval = cycle_interval * mult
	 * So if mult is being incremented by one:
	 *	xtime_interval = cycle_interval * (mult + 1)
	 * Its the same as:
	 *	xtime_interval = (cycle_interval * mult) + cycle_interval
	 * Which can be shortened to:
	 *	xtime_interval += cycle_interval
	 *
	 * So offset stores the non-accumulated cycles. Thus the current
	 * time (in shifted nanoseconds) is:
	 *	now = (offset * adj) + xtime_nsec
	 * Now, even though we're adjusting the clock frequency, we have
	 * to keep time consistent. In other words, we can't jump back
	 * in time, and we also want to avoid jumping forward in time.
	 *
	 * So given the same offset value, we need the time to be the same
	 * both before and after the freq adjustment.
	 *	now = (offset * adj_1) + xtime_nsec_1
	 *	now = (offset * adj_2) + xtime_nsec_2
	 * So:
	 *	(offset * adj_1) + xtime_nsec_1 =
	 *		(offset * adj_2) + xtime_nsec_2
	 * And we know:
	 *	adj_2 = adj_1 + 1
	 * So:
	 *	(offset * adj_1) + xtime_nsec_1 =
	 *		(offset * (adj_1+1)) + xtime_nsec_2
	 *	(offset * adj_1) + xtime_nsec_1 =
	 *		(offset * adj_1) + offset + xtime_nsec_2
	 * Canceling the sides:
	 *	xtime_nsec_1 = offset + xtime_nsec_2
	 * Which gives us:
	 *	xtime_nsec_2 = xtime_nsec_1 - offset
	 * Which simplfies to:
	 *	xtime_nsec -= offset
	 *
	 * XXX - TODO: Doc ntp_error calculation.
	 */
	if ((mult_adj > 0) && (tk->tkr_mono.mult + mult_adj < mult_adj)) {
		/* NTP adjustment caused clocksource mult overflow */
		WARN_ON_ONCE(1);
		return;
	}

	tk->tkr_mono.mult += mult_adj;
	tk->xtime_interval += interval;
	tk->tkr_mono.xtime_nsec -= offset;
	tk->ntp_error -= (interval - offset) << tk->ntp_error_shift;
}

/*
 * Calculate the multiplier adjustment needed to match the frequency
 * specified by NTP
 */
static __always_inline void timekeeping_freqadjust(struct timekeeper *tk,
							s64 offset)
{
	s64 interval = tk->cycle_interval;
	s64 xinterval = tk->xtime_interval;
	u32 base = tk->tkr_mono.clock->mult;
	u32 max = tk->tkr_mono.clock->maxadj;
	u32 cur_adj = tk->tkr_mono.mult;
	s64 tick_error;
	bool negative;
	u32 adj_scale;

	/* Remove any current error adj from freq calculation */
	if (tk->ntp_err_mult)
		xinterval -= tk->cycle_interval;

	tk->ntp_tick = ntp_tick_length();

	/* Calculate current error per tick */
	tick_error = ntp_tick_length() >> tk->ntp_error_shift;
	tick_error -= (xinterval + tk->xtime_remainder);

	/* Don't worry about correcting it if its small */
	if (likely((tick_error >= 0) && (tick_error <= interval)))
		return;

	/* preserve the direction of correction */
	negative = (tick_error < 0);

	/* If any adjustment would pass the max, just return */
	if (negative && (cur_adj - 1) <= (base - max))
		return;
	if (!negative && (cur_adj + 1) >= (base + max))
		return;
	/*
	 * Sort out the magnitude of the correction, but
	 * avoid making so large a correction that we go
	 * over the max adjustment.
	 */
	adj_scale = 0;
	tick_error = abs(tick_error);
	while (tick_error > interval) {
		u32 adj = 1 << (adj_scale + 1);

		/* Check if adjustment gets us within 1 unit from the max */
		if (negative && (cur_adj - adj) <= (base - max))
			break;
		if (!negative && (cur_adj + adj) >= (base + max))
			break;

		adj_scale++;
		tick_error >>= 1;
	}

	/* scale the corrections */
	timekeeping_apply_adjustment(tk, offset, negative, adj_scale);
}

/*
 * Adjust the timekeeper's multiplier to the correct frequency
 * and also to reduce the accumulated error value.
 */
static void timekeeping_adjust(struct timekeeper *tk, s64 offset)
{
	/* Correct for the current frequency error */
	timekeeping_freqadjust(tk, offset);

	/* Next make a small adjustment to fix any cumulative error */
	if (!tk->ntp_err_mult && (tk->ntp_error > 0)) {
		tk->ntp_err_mult = 1;
		timekeeping_apply_adjustment(tk, offset, 0, 0);
	} else if (tk->ntp_err_mult && (tk->ntp_error <= 0)) {
		/* Undo any existing error adjustment */
		timekeeping_apply_adjustment(tk, offset, 1, 0);
		tk->ntp_err_mult = 0;
	}

	if (unlikely(tk->tkr_mono.clock->maxadj &&
		(abs(tk->tkr_mono.mult - tk->tkr_mono.clock->mult)
			> tk->tkr_mono.clock->maxadj))) {
		printk_once(KERN_WARNING
			"Adjusting %s more than 11%% (%ld vs %ld)\n",
			tk->tkr_mono.clock->name, (long)tk->tkr_mono.mult,
			(long)tk->tkr_mono.clock->mult + tk->tkr_mono.clock->maxadj);
	}

	/*
	 * It may be possible that when we entered this function, xtime_nsec
	 * was very small.  Further, if we're slightly speeding the clocksource
	 * in the code above, its possible the required corrective factor to
	 * xtime_nsec could cause it to underflow.
	 *
	 * Now, since we already accumulated the second, cannot simply roll
	 * the accumulated second back, since the NTP subsystem has been
	 * notified via second_overflow. So instead we push xtime_nsec forward
	 * by the amount we underflowed, and add that amount into the error.
	 *
	 * We'll correct this error next time through this function, when
	 * xtime_nsec is not as small.
	 */
	if (unlikely((s64)tk->tkr_mono.xtime_nsec < 0)) {
		s64 neg = -(s64)tk->tkr_mono.xtime_nsec;
		tk->tkr_mono.xtime_nsec = 0;
		tk->ntp_error += neg << tk->ntp_error_shift;
	}
}

/* Uses the current clocksource to increment the wall time */
void update_wall_time(void)
{
	struct timekeeper *real_tk = &tk_core.timekeeper;
	struct timekeeper *tk = &shadow_timekeeper;
	cycle_t offset;
	int shift = 0, maxshift;
	unsigned int clock_set = 0;
	unsigned long flags;

	spin_lock_irqsave(&timekeeper_lock, flags);

	offset = clocksource_delta(tk_clock_read(&tk->tkr_mono),
				   tk->tkr_mono.cycle_last, tk->tkr_mono.mask);

	/* Check if there's really nothing to do */
	if (offset < real_tk->cycle_interval)
		goto out;

	/* Do some additional sanity checking */
	timekeeping_check_update(real_tk, offset);

	/*
	 * With NO_HZ we may have to accumulate many cycle_intervals
	 * (think "ticks") worth of time at once. To do this efficiently,
	 * we calculate the largest doubling multiple of cycle_intervals
	 * that is smaller than the offset.  We then accumulate that
	 * chunk in one go, and then try to consume the next smaller
	 * doubled multiple.
	 */
	shift = ilog2(offset) - ilog2(tk->cycle_interval);
	shift = max(0, shift);
	/* Bound shift to one less than what overflows tick_length */
	maxshift = (64 - (ilog2(ntp_tick_length())+1)) - 1;
	shift = min(shift, maxshift);
	while (offset >= tk->cycle_interval) {
		offset = logarithmic_accumulation(tk, offset, shift,
							&clock_set);
		if (offset < tk->cycle_interval<<shift)
			shift--;
	}

	/* correct the clock when NTP error is too big */
	timekeeping_adjust(tk, offset);

	/*
	 * Finally, make sure that after the rounding
	 * xtime_nsec isn't larger than NSEC_PER_SEC
	 */
	clock_set |= accumulate_nsecs_to_secs(tk);

	write_seqcount_begin(&tk_core.seq);
	/*
	 * Update the real timekeeper.
	 *
	 * We could avoid this memcpy by switching pointers, but that
	 * requires changes to all other timekeeper usage sites as
	 * well, i.e. move the timekeeper pointer getter into the
	 * spinlocked/seqcount protected sections. And we trade this
	 * memcpy under the tk_core.seq against one before we start
	 * updating.
	 */
	timekeeping_update(tk, clock_set);
	memcpy(real_tk, tk, sizeof(*tk));
	/* The memcpy must come last. Do not put anything here! */
	write_seqcount_end(&tk_core.seq);
out:
	spin_unlock_irqrestore(&timekeeper_lock, flags);
}

/**
 * timekeeping_forward_now - update clock to the current time
 *
 * Forward the current clock to update its state since the last call to
 * update_wall_time(). This is useful before significant clock changes,
 * as it avoids having to deal with this time offset explicitly.
 */
static void timekeeping_forward_now(struct timekeeper *tk)
{
	cycle_t cycle_now, delta;
	s64 nsec;

	cycle_now = tk_clock_read(&tk->tkr_mono);
	delta = clocksource_delta(cycle_now, tk->tkr_mono.cycle_last, tk->tkr_mono.mask);
	tk->tkr_mono.cycle_last = cycle_now;
	tk->tkr_raw.cycle_last  = cycle_now;

	tk->tkr_mono.xtime_nsec += delta * tk->tkr_mono.mult;

	tk_normalize_xtime(tk);

	nsec = clocksource_cyc2ns(delta, tk->tkr_raw.mult, tk->tkr_raw.shift);
	timespec_add_ns(&tk->raw_time, nsec);
}

/**
 * change_clocksource - Swaps clocksources if a new one is available
 *
 * Accumulates current time interval and initializes new clocksource
 */
static int change_clocksource(struct clocksource *new)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	struct clocksource *old;
	unsigned long flags;

	spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&tk_core.seq);

	timekeeping_forward_now(tk);

	if (!new->enable || new->enable(new) == 0) {
		old = tk->tkr_mono.clock;
		tk_setup_internals(tk, new);
		if (old && old->disable)
			old->disable(old);
	}

	timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&tk_core.seq);
	spin_unlock_irqrestore(&timekeeper_lock, flags);

	return 0;
}

/**
 * timekeeping_notify - Install a new clock source
 * @clock:		pointer to the clock source
 *
 * This function is called from clocksource.c after a new, better clock
 * source has been registered. The caller holds the clocksource_mutex.
 */
int timekeeping_notify(struct clocksource *clock)
{
	struct timekeeper *tk = &tk_core.timekeeper;

	if (tk->tkr_mono.clock == clock)
		return 0;
	change_clocksource(clock);
	return tk->tkr_mono.clock == clock ? 0 : -1;
}

/*
 * timekeeping_init
 * Initializes the clocksource and common timekeeping values
 */
void __init timekeeping_init(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	struct clocksource *clock;
	struct timespec now, boot, tmp;
	unsigned long flags;

	read_persistent_clock(&now);

	if (!timespec_valid_strict(&now)) {
		pr_warn("WARNING: Persistent clock returned invalid value!\n"
			"         Check your CMOS/BIOS settings.\n");
		now.tv_sec = 0;
		now.tv_nsec = 0;
	} else if (now.tv_sec || now.tv_nsec)
		persistent_clock_exists = true;

	spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&tk_core.seq);
	ntp_init();

	/*
	 * We are called before time_init(), so better clocksources
	 * are not even registered. So we use our default jiffies
	 * clocksource first. Later on if time_init() registe better
	 * ones, it will use timekeeping_notify() to tell us:
	 *
	 * Why jiffies can a clocksource? Because jiffies is updated
	 * during every timer interrupt. So it is sort of a software
	 * clocksource, and it has granunality of 1 HZ.
	 *
	 * Of course, timer interrupt is fired by clockevent devices.
	 */
	clock = clocksource_default_clock();
	if (clock->enable)
		clock->enable(clock);

	tk_setup_internals(tk, clock);
	tk_set_xtime(tk, &now);
	tk->raw_time.tv_sec = 0;
	tk->raw_time.tv_nsec = 0;

	boot = tk_xtime(tk);
	set_normalized_timespec(&tmp, -boot.tv_sec, -boot.tv_nsec);
	tk_set_wall_to_mono(tk, tmp);

	timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&tk_core.seq);
	spin_unlock_irqrestore(&timekeeper_lock, flags);
}

/**
 * ktime_get_seconds - Get the seconds portion of CLOCK_MONOTONIC
 *
 * Returns the seconds portion of CLOCK_MONOTONIC with a single non
 * serialized read. tk->ktime_sec is of type 'unsigned long' so this
 * works on both 32 and 64 bit systems. On 32 bit systems the readout
 * covers ~136 years of uptime which should be enough to prevent
 * premature wrap arounds.
 */
time_t ktime_get_seconds(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	return tk->ktime_sec;
}

/**
 * ktime_get_real_seconds - Get the seconds portion of CLOCK_REALTIME
 *
 * Returns the wall clock seconds since 1970. This replaces the
 * get_seconds() interface which is not y2038 safe on 32bit systems.
 *
 * For 64bit systems the fast access to tk->xtime_sec is preserved. On
 * 32bit systems the access must be protected with the sequence
 * counter to provide "atomic" access to the 64bit tk->xtime_sec
 * value.
 */
time_t ktime_get_real_seconds(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	return tk->xtime_sec;
}

/**
 * __ktime_get_real_seconds - The same as ktime_get_real_seconds
 * but without the sequence counter protect. This internal function
 * is called just when timekeeping lock is already held.
 */
time_t __ktime_get_real_seconds(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	return tk->xtime_sec;
}

unsigned long get_seconds(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	return tk->xtime_sec;
}

struct timespec current_kernel_time(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	struct timespec now;
	unsigned long seq;

	do {
		seq = read_seqcount_begin(&tk_core.seq);

		now = tk_xtime(tk);
	} while (read_seqcount_retry(&tk_core.seq, seq));

	return now;
}

static inline u64 timekeeping_delta_to_ns(struct tk_read_base *tkr,
					  cycle_t delta)
{
	u64 nsec;

	nsec = delta * tkr->mult + tkr->xtime_nsec;
	nsec >>= tkr->shift;

	return nsec;
}

static inline s64 timekeeping_get_ns(struct tk_read_base *tkr)
{
	cycle_t delta;

	delta = timekeeping_get_delta(tkr);
	return timekeeping_delta_to_ns(tkr, delta);
}

/**
 *  Returns the time of day in a timespec.
 * @ts:		pointer to the timespec to be set
 *
 * Updates the time of day in the timespec.
 * Returns 0 on success, or -ve when suspended (timespec will be undefined).
 */
int __do_gettimeofday(struct timespec *ts)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	unsigned long seq;
	s64 nsecs = 0;

	do {
		seq = read_seqcount_begin(&tk_core.seq);

		ts->tv_sec = tk->xtime_sec;
		nsecs = timekeeping_get_ns(&tk->tkr_mono);

	} while (read_seqcount_retry(&tk_core.seq, seq));

	ts->tv_nsec = 0;
	timespec_add_ns(ts, nsecs);

	return 0;
}

ktime_t ktime_get(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	ktime_t base;
	unsigned int seq;
	s64 nsecs;

	do {
		seq = read_seqcount_begin(&tk_core.seq);
		base = tk->tkr_mono.base;
		nsecs = timekeeping_get_ns(&tk->tkr_mono);

	} while (read_seqcount_retry(&tk_core.seq, seq));

	return ktime_add_ns(base, nsecs);
}

static ktime_t *offsets[TK_OFFS_MAX] = {
	[TK_OFFS_REAL]	= &tk_core.timekeeper.offs_real,
	[TK_OFFS_BOOT]	= &tk_core.timekeeper.offs_boot,
	[TK_OFFS_TAI]	= &tk_core.timekeeper.offs_tai,
};

ktime_t ktime_get_with_offset(enum tk_offsets offs)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	unsigned int seq;
	ktime_t base, *offset = offsets[offs];
	s64 nsecs;

	do {
		seq = read_seqcount_begin(&tk_core.seq);
		base = ktime_add(tk->tkr_mono.base, *offset);
		nsecs = timekeeping_get_ns(&tk->tkr_mono);

	} while (read_seqcount_retry(&tk_core.seq, seq));

	return ktime_add_ns(base, nsecs);
}

/**
 * getboottime - Return the real time of system boot.
 * @ts:		pointer to the timespec64 to be set
 *
 * Returns the wall-time of boot in a timespec
 *
 * This is based on the wall_to_monotonic offset and the total suspend
 * time. Calls to settimeofday will affect the value returned (which
 * basically means that however wrong your real time clock is at boot time,
 * you get the right time here).
 */
void getboottime(struct timespec *ts)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	ktime_t t = ktime_sub(tk->offs_real, tk->offs_boot);

	*ts = ktime_to_timespec(t);
}

void do_timer(unsigned long ticks)
{
	jiffies += ticks;
}
