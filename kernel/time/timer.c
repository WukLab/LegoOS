/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/list.h>
#include <lego/sched.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>

/*
 * The timer wheel has LVL_DEPTH array levels. Each level provides an array of
 * LVL_SIZE buckets. Each level is driven by its own clock and therefor each
 * level has a different granularity.
 *
 * The level granularity is:		LVL_CLK_DIV ^ lvl
 * The level clock frequency is:	HZ / (LVL_CLK_DIV ^ level)
 *
 * The array level of a newly armed timer depends on the relative expiry
 * time. The farther the expiry time is away the higher the array level and
 * therefor the granularity becomes.
 *
 * Contrary to the original timer wheel implementation, which aims for 'exact'
 * expiry of the timers, this implementation removes the need for recascading
 * the timers into the lower array levels. The previous 'classic' timer wheel
 * implementation of the kernel already violated the 'exact' expiry by adding
 * slack to the expiry time to provide batched expiration. The granularity
 * levels provide implicit batching.
 *
 * This is an optimization of the original timer wheel implementation for the
 * majority of the timer wheel use cases: timeouts. The vast majority of
 * timeout timers (networking, disk I/O ...) are canceled before expiry. If
 * the timeout expires it indicates that normal operation is disturbed, so it
 * does not matter much whether the timeout comes with a slight delay.
 *
 * The only exception to this are networking timers with a small expiry
 * time. They rely on the granularity. Those fit into the first wheel level,
 * which has HZ granularity.
 *
 * We don't have cascading anymore. timers with a expiry time above the
 * capacity of the last wheel level are force expired at the maximum timeout
 * value of the last wheel level. From data sampling we know that the maximum
 * value observed is 5 days (network connection tracking), so this should not
 * be an issue.
 *
 * The currently chosen array constants values are a good compromise between
 * array size and granularity.
 *
 * This results in the following granularity and range levels:
 *
 * HZ 1000 steps
 * Level Offset  Granularity            Range
 *  0      0         1 ms                0 ms -         63 ms
 *  1     64         8 ms               64 ms -        511 ms
 *  2    128        64 ms              512 ms -       4095 ms (512ms - ~4s)
 *  3    192       512 ms             4096 ms -      32767 ms (~4s - ~32s)
 *  4    256      4096 ms (~4s)      32768 ms -     262143 ms (~32s - ~4m)
 *  5    320     32768 ms (~32s)    262144 ms -    2097151 ms (~4m - ~34m)
 *  6    384    262144 ms (~4m)    2097152 ms -   16777215 ms (~34m - ~4h)
 *  7    448   2097152 ms (~34m)  16777216 ms -  134217727 ms (~4h - ~1d)
 *  8    512  16777216 ms (~4h)  134217728 ms - 1073741822 ms (~1d - ~12d)
 *
 * HZ  300
 * Level Offset  Granularity            Range
 *  0	   0         3 ms                0 ms -        210 ms
 *  1	  64        26 ms              213 ms -       1703 ms (213ms - ~1s)
 *  2	 128       213 ms             1706 ms -      13650 ms (~1s - ~13s)
 *  3	 192      1706 ms (~1s)      13653 ms -     109223 ms (~13s - ~1m)
 *  4	 256     13653 ms (~13s)    109226 ms -     873810 ms (~1m - ~14m)
 *  5	 320    109226 ms (~1m)     873813 ms -    6990503 ms (~14m - ~1h)
 *  6	 384    873813 ms (~14m)   6990506 ms -   55924050 ms (~1h - ~15h)
 *  7	 448   6990506 ms (~1h)   55924053 ms -  447392423 ms (~15h - ~5d)
 *  8    512  55924053 ms (~15h) 447392426 ms - 3579139406 ms (~5d - ~41d)
 *
 * HZ  250
 * Level Offset  Granularity            Range
 *  0	   0         4 ms                0 ms -        255 ms
 *  1	  64        32 ms              256 ms -       2047 ms (256ms - ~2s)
 *  2	 128       256 ms             2048 ms -      16383 ms (~2s - ~16s)
 *  3	 192      2048 ms (~2s)      16384 ms -     131071 ms (~16s - ~2m)
 *  4	 256     16384 ms (~16s)    131072 ms -    1048575 ms (~2m - ~17m)
 *  5	 320    131072 ms (~2m)    1048576 ms -    8388607 ms (~17m - ~2h)
 *  6	 384   1048576 ms (~17m)   8388608 ms -   67108863 ms (~2h - ~18h)
 *  7	 448   8388608 ms (~2h)   67108864 ms -  536870911 ms (~18h - ~6d)
 *  8    512  67108864 ms (~18h) 536870912 ms - 4294967288 ms (~6d - ~49d)
 *
 * HZ  100
 * Level Offset  Granularity            Range
 *  0	   0         10 ms               0 ms -        630 ms
 *  1	  64         80 ms             640 ms -       5110 ms (640ms - ~5s)
 *  2	 128        640 ms            5120 ms -      40950 ms (~5s - ~40s)
 *  3	 192       5120 ms (~5s)     40960 ms -     327670 ms (~40s - ~5m)
 *  4	 256      40960 ms (~40s)   327680 ms -    2621430 ms (~5m - ~43m)
 *  5	 320     327680 ms (~5m)   2621440 ms -   20971510 ms (~43m - ~5h)
 *  6	 384    2621440 ms (~43m) 20971520 ms -  167772150 ms (~5h - ~1d)
 *  7	 448   20971520 ms (~5h) 167772160 ms - 1342177270 ms (~1d - ~15d)
 *
 * More
 *	https://lwn.net/Articles/646056/
 *	https://lwn.net/Articles/646950/
 */

/* Clock divisor for the next level */
#define LVL_CLK_SHIFT	3
#define LVL_CLK_DIV	(1UL << LVL_CLK_SHIFT)
#define LVL_CLK_MASK	(LVL_CLK_DIV - 1)
#define LVL_SHIFT(n)	((n) * LVL_CLK_SHIFT)
#define LVL_GRAN(n)	(1UL << LVL_SHIFT(n))

/*
 * The time start value for each level to select the bucket at enqueue
 * time.
 */
#define LVL_START(n)	((LVL_SIZE - 1) << (((n) - 1) * LVL_CLK_SHIFT))

/* Size of each clock level */
#define LVL_BITS	6
#define LVL_SIZE	(1UL << LVL_BITS)
#define LVL_MASK	(LVL_SIZE - 1)
#define LVL_OFFS(n)	((n) * LVL_SIZE)

/* Level depth */
#if HZ > 100
# define LVL_DEPTH	9
# else
# define LVL_DEPTH	8
#endif

/* The cutoff (max. capacity of the wheel) */
#define WHEEL_TIMEOUT_CUTOFF	(LVL_START(LVL_DEPTH))
#define WHEEL_TIMEOUT_MAX	(WHEEL_TIMEOUT_CUTOFF - LVL_GRAN(LVL_DEPTH - 1))

/*
 * The resulting wheel size. If NOHZ is configured we allocate two
 * wheels so we have a separate storage for the deferrable timers.
 */
#define WHEEL_SIZE	(LVL_SIZE * LVL_DEPTH)

#ifdef CONFIG_NO_HZ_COMMON
# define NR_BASES	2
# define BASE_STD	0
# define BASE_DEF	1
#else
# define NR_BASES	1
# define BASE_STD	0
# define BASE_DEF	0
#endif

struct timer_base {
	spinlock_t		lock;
	struct timer_list	*running_timer;
	unsigned long		clk;
	unsigned long		next_expiry;
	unsigned int		cpu;
	bool			migration_enabled;
	bool			nohz_active;
	bool			is_idle;
	DECLARE_BITMAP(pending_map, WHEEL_SIZE);
	struct hlist_head	vectors[WHEEL_SIZE];
} ____cacheline_aligned;

static DEFINE_PER_CPU(struct timer_base, timer_bases[NR_BASES]);

static unsigned long round_jiffies_common(unsigned long j, int cpu,
		bool force_up)
{
	int rem;
	unsigned long original = j;

	/*
	 * We don't want all cpus firing their timers at once hitting the
	 * same lock or cachelines, so we skew each extra cpu with an extra
	 * 3 jiffies. This 3 jiffies came originally from the mm/ code which
	 * already did this.
	 * The skew is done by adding 3*cpunr, then round, then subtract this
	 * extra offset again.
	 */
	j += cpu * 3;

	rem = j % HZ;

	/*
	 * If the target jiffie is just after a whole second (which can happen
	 * due to delays of the timer irq, long irq off times etc etc) then
	 * we should round down to the whole second, not up. Use 1/4th second
	 * as cutoff for this rounding as an extreme upper bound for this.
	 * But never round down if @force_up is set.
	 */
	if (rem < HZ/4 && !force_up) /* round down */
		j = j - rem;
	else /* round up */
		j = j - rem + HZ;

	/* now that we have rounded, subtract the extra skew again */
	j -= cpu * 3;

	/*
	 * Make sure j is still in the future. Otherwise return the
	 * unmodified value.
	 */
	return time_is_after_jiffies(j) ? j : original;
}

/**
 * __round_jiffies - function to round jiffies to a full second
 * @j: the time in (absolute) jiffies that should be rounded
 * @cpu: the processor number on which the timeout will happen
 *
 * __round_jiffies() rounds an absolute time in the future (in jiffies)
 * up or down to (approximately) full seconds. This is useful for timers
 * for which the exact time they fire does not matter too much, as long as
 * they fire approximately every X seconds.
 *
 * By rounding these timers to whole seconds, all such timers will fire
 * at the same time, rather than at various times spread out. The goal
 * of this is to have the CPU wake up less, which saves power.
 *
 * The exact rounding is skewed for each processor to avoid all
 * processors firing at the exact same time, which could lead
 * to lock contention or spurious cache line bouncing.
 *
 * The return value is the rounded version of the @j parameter.
 */
unsigned long __round_jiffies(unsigned long j, int cpu)
{
	return round_jiffies_common(j, cpu, false);
}

/**
 * __round_jiffies_relative - function to round jiffies to a full second
 * @j: the time in (relative) jiffies that should be rounded
 * @cpu: the processor number on which the timeout will happen
 *
 * __round_jiffies_relative() rounds a time delta  in the future (in jiffies)
 * up or down to (approximately) full seconds. This is useful for timers
 * for which the exact time they fire does not matter too much, as long as
 * they fire approximately every X seconds.
 *
 * By rounding these timers to whole seconds, all such timers will fire
 * at the same time, rather than at various times spread out. The goal
 * of this is to have the CPU wake up less, which saves power.
 *
 * The exact rounding is skewed for each processor to avoid all
 * processors firing at the exact same time, which could lead
 * to lock contention or spurious cache line bouncing.
 *
 * The return value is the rounded version of the @j parameter.
 */
unsigned long __round_jiffies_relative(unsigned long j, int cpu)
{
	unsigned long j0 = jiffies;

	/* Use j0 because jiffies might change while we run */
	return round_jiffies_common(j + j0, cpu, false) - j0;
}

/**
 * round_jiffies - function to round jiffies to a full second
 * @j: the time in (absolute) jiffies that should be rounded
 *
 * round_jiffies() rounds an absolute time in the future (in jiffies)
 * up or down to (approximately) full seconds. This is useful for timers
 * for which the exact time they fire does not matter too much, as long as
 * they fire approximately every X seconds.
 *
 * By rounding these timers to whole seconds, all such timers will fire
 * at the same time, rather than at various times spread out. The goal
 * of this is to have the CPU wake up less, which saves power.
 *
 * The return value is the rounded version of the @j parameter.
 */
unsigned long round_jiffies(unsigned long j)
{
	return round_jiffies_common(j, smp_processor_id(), false);
}

/**
 * round_jiffies_relative - function to round jiffies to a full second
 * @j: the time in (relative) jiffies that should be rounded
 *
 * round_jiffies_relative() rounds a time delta  in the future (in jiffies)
 * up or down to (approximately) full seconds. This is useful for timers
 * for which the exact time they fire does not matter too much, as long as
 * they fire approximately every X seconds.
 *
 * By rounding these timers to whole seconds, all such timers will fire
 * at the same time, rather than at various times spread out. The goal
 * of this is to have the CPU wake up less, which saves power.
 *
 * The return value is the rounded version of the @j parameter.
 */
unsigned long round_jiffies_relative(unsigned long j)
{
	return __round_jiffies_relative(j, smp_processor_id());
}

/**
 * __round_jiffies_up_relative - function to round jiffies up to a full second
 * @j: the time in (relative) jiffies that should be rounded
 * @cpu: the processor number on which the timeout will happen
 *
 * This is the same as __round_jiffies_relative() except that it will never
 * round down.  This is useful for timeouts for which the exact time
 * of firing does not matter too much, as long as they don't fire too
 * early.
 */
unsigned long __round_jiffies_up_relative(unsigned long j, int cpu)
{
	unsigned long j0 = jiffies;

	/* Use j0 because jiffies might change while we run */
	return round_jiffies_common(j + j0, cpu, true) - j0;
}

/**
 * round_jiffies_up - function to round jiffies up to a full second
 * @j: the time in (absolute) jiffies that should be rounded
 *
 * This is the same as round_jiffies() except that it will never
 * round down.  This is useful for timeouts for which the exact time
 * of firing does not matter too much, as long as they don't fire too
 * early.
 */
unsigned long round_jiffies_up(unsigned long j)
{
	return round_jiffies_common(j, smp_processor_id(), true);
}

/**
 * round_jiffies_up_relative - function to round jiffies up to a full second
 * @j: the time in (relative) jiffies that should be rounded
 *
 * This is the same as round_jiffies_relative() except that it will never
 * round down.  This is useful for timeouts for which the exact time
 * of firing does not matter too much, as long as they don't fire too
 * early.
 */
unsigned long round_jiffies_up_relative(unsigned long j)
{
	return __round_jiffies_up_relative(j, smp_processor_id());
}

static inline unsigned int timer_get_idx(struct timer_list *timer)
{
	return (timer->flags & TIMER_ARRAYMASK) >> TIMER_ARRAYSHIFT;
}

static inline void timer_set_idx(struct timer_list *timer, unsigned int idx)
{
	timer->flags = (timer->flags & ~TIMER_ARRAYMASK) |
			idx << TIMER_ARRAYSHIFT;
}

/*
 * Helper function to calculate the array index for a given expiry
 * time.
 */
static inline unsigned calc_index(unsigned expires, unsigned lvl)
{
	expires = (expires + LVL_GRAN(lvl)) >> LVL_SHIFT(lvl);
	return LVL_OFFS(lvl) + (expires & LVL_MASK);
}

static int calc_wheel_index(unsigned long expires, unsigned long clk)
{
	unsigned long delta = expires - clk;
	unsigned int idx;

	if (delta < LVL_START(1)) {
		idx = calc_index(expires, 0);
	} else if (delta < LVL_START(2)) {
		idx = calc_index(expires, 1);
	} else if (delta < LVL_START(3)) {
		idx = calc_index(expires, 2);
	} else if (delta < LVL_START(4)) {
		idx = calc_index(expires, 3);
	} else if (delta < LVL_START(5)) {
		idx = calc_index(expires, 4);
	} else if (delta < LVL_START(6)) {
		idx = calc_index(expires, 5);
	} else if (delta < LVL_START(7)) {
		idx = calc_index(expires, 6);
	} else if (LVL_DEPTH > 8 && delta < LVL_START(8)) {
		idx = calc_index(expires, 7);
	} else if ((long) delta < 0) {
		idx = clk & LVL_MASK;
	} else {
		/*
		 * Force expire obscene large timeouts to expire at the
		 * capacity limit of the wheel.
		 */
		if (expires >= WHEEL_TIMEOUT_CUTOFF)
			expires = WHEEL_TIMEOUT_MAX;

		idx = calc_index(expires, LVL_DEPTH - 1);
	}
	return idx;
}

/*
 * Enqueue the timer into the hash bucket, mark it pending in
 * the bitmap and store the index in the timer flags.
 */
static void enqueue_timer(struct timer_base *base, struct timer_list *timer,
			  unsigned int idx)
{
	hlist_add_head(&timer->entry, base->vectors + idx);
	__set_bit(idx, base->pending_map);
	timer_set_idx(timer, idx);
}

static void internal_add_timer(struct timer_base *base, struct timer_list *timer)
{
	unsigned int idx;

	idx = calc_wheel_index(timer->expires, base->clk);
	enqueue_timer(base, timer, idx);
}

/**
 * __init_timer - initialize a timer
 *
 * __init_timer() must be done to a timer prior calling *any* of the
 * other timer functions.
 */
void __init_timer(struct timer_list *timer, unsigned int flags)
{
	timer->entry.pprev = NULL;
	timer->flags = flags | smp_processor_id();
}

static inline void detach_timer(struct timer_list *timer, bool clear_pending)
{
	struct hlist_node *entry = &timer->entry;

	__hlist_del(entry);
	if (clear_pending)
		entry->pprev = NULL;
	entry->next = LIST_POISON2;
}

static int detach_if_pending(struct timer_list *timer, struct timer_base *base,
			     bool clear_pending)
{
	unsigned idx = timer_get_idx(timer);

	if (!timer_pending(timer))
		return 0;

	if (hlist_is_singular_node(&timer->entry, base->vectors + idx))
		__clear_bit(idx, base->pending_map);

	detach_timer(timer, clear_pending);
	return 1;
}

static inline struct timer_base *get_timer_cpu_base(u32 tflags, u32 cpu)
{
	return per_cpu_ptr(&timer_bases[BASE_STD], cpu);
}

static inline struct timer_base *get_timer_this_cpu_base(u32 tflags)
{
	return this_cpu_ptr(&timer_bases[BASE_STD]);
}

static inline struct timer_base *get_timer_base(u32 tflags)
{
	return get_timer_cpu_base(tflags, tflags & TIMER_CPUMASK);
}

static inline struct timer_base *get_target_base(struct timer_base *base, unsigned tflags)
{
	return get_timer_this_cpu_base(tflags);
}

/*
 * We are using hashed locking: Holding per_cpu(timer_bases[x]).lock means
 * that all timers which are tied to this base are locked, and the base itself
 * is locked too.
 *
 * So __run_timers/migrate_timers can safely modify all timers which could
 * be found in the base->vectors array.
 *
 * When a timer is migrating then the TIMER_MIGRATING flag is set and we need
 * to wait until the migration is done.
 */
static struct timer_base *lock_timer_base(struct timer_list *timer,
					  unsigned long *flags)
	__acquires(timer->base->lock)
{
	for (;;) {
		struct timer_base *base;
		u32 tf;

		/*
		 * We need to use READ_ONCE() here, otherwise the compiler
		 * might re-read @tf between the check for TIMER_MIGRATING
		 * and spin_lock().
		 */
		tf = READ_ONCE(timer->flags);

		if (!(tf & TIMER_MIGRATING)) {
			base = get_timer_base(tf);
			spin_lock_irqsave(&base->lock, *flags);
			if (timer->flags == tf)
				return base;
			spin_unlock_irqrestore(&base->lock, *flags);
		}
		cpu_relax();
	}
}

static inline int
__mod_timer(struct timer_list *timer, unsigned long expires, bool pending_only)
{
	struct timer_base *base, *new_base;
	unsigned int idx = UINT_MAX;
	unsigned long clk = 0, flags;
	int ret = 0;

	BUG_ON(!timer->function);

	/*
	 * This is a common optimization triggered by the networking code - if
	 * the timer is re-modified to have the same timeout or ends up in the
	 * same array bucket then just return:
	 */
	if (timer_pending(timer)) {
		if (timer->expires == expires)
			return 1;

		/*
		 * We lock timer base and calculate the bucket index right
		 * here. If the timer ends up in the same bucket, then we
		 * just update the expiry time and avoid the whole
		 * dequeue/enqueue dance.
		 */
		base = lock_timer_base(timer, &flags);

		clk = base->clk;
		idx = calc_wheel_index(expires, clk);

		/*
		 * Retrieve and compare the array index of the pending
		 * timer. If it matches set the expiry to the new value so a
		 * subsequent call will exit in the expires check above.
		 */
		if (idx == timer_get_idx(timer)) {
			timer->expires = expires;
			ret = 1;
			goto out_unlock;
		}
	} else {
		base = lock_timer_base(timer, &flags);
	}

	ret = detach_if_pending(timer, base, false);
	if (!ret && pending_only)
		goto out_unlock;

	new_base = get_target_base(base, timer->flags);
	if (base != new_base) {
		/*
		 * We are trying to schedule the timer on the new base.
		 * However we can't change timer's base while it is running,
		 * otherwise del_timer_sync() can't detect that the timer's
		 * handler yet has not finished. This also guarantees that the
		 * timer is serialized wrt itself.
		 */
		if (likely(base->running_timer != timer)) {
			/* See the comment in lock_timer_base() */
			timer->flags |= TIMER_MIGRATING;

			spin_unlock(&base->lock);
			base = new_base;
			spin_lock(&base->lock);
			WRITE_ONCE(timer->flags,
				   (timer->flags & ~TIMER_BASEMASK) | base->cpu);
		}
	}

	timer->expires = expires;
	/*
	 * If 'idx' was calculated above and the base time did not advance
	 * between calculating 'idx' and possibly switching the base, only
	 * enqueue_timer() and trigger_dyntick_cpu() is required. Otherwise
	 * we need to (re)calculate the wheel index via
	 * internal_add_timer().
	 */
	if (idx != UINT_MAX && clk == base->clk)
		enqueue_timer(base, timer, idx);
	else
		internal_add_timer(base, timer);

out_unlock:
	spin_unlock_irqrestore(&base->lock, flags);

	return ret;

}

/**
 * mod_timer_pending - modify a pending timer's timeout
 * @timer: the pending timer to be modified
 * @expires: new timeout in jiffies
 *
 * mod_timer_pending() is the same for pending timers as mod_timer(),
 * but will not re-activate and modify already deleted timers.
 *
 * It is useful for unserialized use of timers.
 */
int mod_timer_pending(struct timer_list *timer, unsigned long expires)
{
	return __mod_timer(timer, expires, true);
}

/**
 * mod_timer - modify a timer's timeout
 * @timer: the timer to be modified
 * @expires: new timeout in jiffies
 *
 * mod_timer() is a more efficient way to update the expire field of an
 * active timer (if the timer is inactive it will be activated)
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * The function returns whether it has modified a pending timer or not.
 * (ie. mod_timer() of an inactive timer returns 0, mod_timer() of an
 * active timer returns 1.)
 */
int mod_timer(struct timer_list *timer, unsigned long expires)
{
	return __mod_timer(timer, expires, false);
}

/**
 * add_timer - start a timer
 * @timer: the timer to be added
 *
 * The kernel will do a ->function(->data) callback from the
 * timer interrupt at the ->expires point in the future. The
 * current time is 'jiffies'.
 *
 * The timer's ->expires, ->function (and if the handler uses it, ->data)
 * fields must be set prior calling this function.
 *
 * Timers with an ->expires field in the past will be executed in the next
 * timer tick.
 */
void add_timer(struct timer_list *timer)
{
	BUG_ON(timer_pending(timer));
	mod_timer(timer, timer->expires);
}

/**
 * add_timer_on - start a timer on a particular CPU
 * @timer: the timer to be added
 * @cpu: the CPU to start it on
 *
 * This is not very scalable on SMP. Double adds are not possible.
 */
void add_timer_on(struct timer_list *timer, int cpu)
{
	struct timer_base *new_base, *base;
	unsigned long flags;

	BUG_ON(timer_pending(timer) || !timer->function);

	new_base = get_timer_cpu_base(timer->flags, cpu);

	/*
	 * If @timer was on a different CPU, it should be migrated with the
	 * old base locked to prevent other operations proceeding with the
	 * wrong base locked.  See lock_timer_base().
	 */
	base = lock_timer_base(timer, &flags);
	if (base != new_base) {
		timer->flags |= TIMER_MIGRATING;

		spin_unlock(&base->lock);
		base = new_base;
		spin_lock(&base->lock);
		WRITE_ONCE(timer->flags,
			   (timer->flags & ~TIMER_BASEMASK) | cpu);
	}

	internal_add_timer(base, timer);
	spin_unlock_irqrestore(&base->lock, flags);
}

/**
 * del_timer - deactive a timer.
 * @timer: the timer to be deactivated
 *
 * del_timer() deactivates a timer - this works on both active and inactive
 * timers.
 *
 * The function returns whether it has deactivated a pending timer or not.
 * (ie. del_timer() of an inactive timer returns 0, del_timer() of an
 * active timer returns 1.)
 */
int del_timer(struct timer_list *timer)
{
	struct timer_base *base;
	unsigned long flags;
	int ret = 0;

	if (timer_pending(timer)) {
		base = lock_timer_base(timer, &flags);
		ret = detach_if_pending(timer, base, true);
		spin_unlock_irqrestore(&base->lock, flags);
	}

	return ret;
}

/**
 * try_to_del_timer_sync - Try to deactivate a timer
 * @timer: timer do del
 *
 * This function tries to deactivate a timer. Upon successful (ret >= 0)
 * exit the timer is not queued and the handler is not running on any CPU.
 */
int try_to_del_timer_sync(struct timer_list *timer)
{
	struct timer_base *base;
	unsigned long flags;
	int ret = -1;

	base = lock_timer_base(timer, &flags);
	if (base->running_timer != timer)
		ret = detach_if_pending(timer, base, true);
	spin_unlock_irqrestore(&base->lock, flags);

	return ret;
}

#ifdef CONFIG_SMP
/**
 * del_timer_sync - deactivate a timer and wait for the handler to finish.
 * @timer: the timer to be deactivated
 *
 * This function only differs from del_timer() on SMP: besides deactivating
 * the timer it also makes sure the handler has finished executing on other
 * CPUs.
 *
 * Synchronization rules: Callers must prevent restarting of the timer,
 * otherwise this function is meaningless. It must not be called from
 * interrupt contexts unless the timer is an irqsafe one. The caller must
 * not hold locks which would prevent completion of the timer's
 * handler. The timer's handler must not call add_timer_on(). Upon exit the
 * timer is not queued and the handler is not running on any CPU.
 *
 * Note: For !irqsafe timers, you must not hold locks that are held in
 *   interrupt context while calling this function. Even if the lock has
 *   nothing to do with the timer in question.  Here's why:
 *
 *    CPU0                             CPU1
 *    ----                             ----
 *                                   <SOFTIRQ>
 *                                   call_timer_fn();
 *                                     base->running_timer = mytimer;
 *  spin_lock_irq(somelock);
 *                                     <IRQ>
 *                                        spin_lock(somelock);
 *  del_timer_sync(mytimer);
 *   while (base->running_timer == mytimer);
 *
 * Now del_timer_sync() will never return and never release somelock.
 * The interrupt on the other CPU is waiting to grab somelock but
 * it has interrupted the softirq that CPU0 is waiting to finish.
 *
 * The function returns whether it has deactivated a pending timer or not.
 */
int del_timer_sync(struct timer_list *timer)
{
	/*
	 * don't use it in hardirq context, because it
	 * could lead to deadlock.
	 */
	WARN_ON(irqs_disabled() && !(timer->flags & TIMER_IRQSAFE));
	for (;;) {
		int ret = try_to_del_timer_sync(timer);
		if (ret >= 0)
			return ret;
		cpu_relax();
	}
}
#endif

static void call_timer_fn(struct timer_list *timer, void (*fn)(unsigned long),
			  unsigned long data)
{
	int count = preempt_count();

	fn(data);

	if (unlikely(count != preempt_count())) {
		WARN_ONCE(1, "timer: %pF preempt leak: %08x -> %08x\n",
			  fn, count, preempt_count());
		/*
		 * Restore the preempt count. That gives us a decent
		 * chance to survive and extract information. If the
		 * callback kept a lock held, bad luck, but not worse
		 * than the BUG() we had.
		 */
		preempt_count_set(count);
	}

	if (unlikely(!irqs_disabled())) {
		WARN_ONCE(1, "timer: %pF enabled interrupt\n", fn);
		local_irq_disable();
	}
}

static void expire_timers(struct timer_base *base, struct hlist_head *head)
{
	while (!hlist_empty(head)) {
		struct timer_list *timer;
		void (*fn)(unsigned long);
		unsigned long data;

		timer = hlist_entry(head->first, struct timer_list, entry);

		base->running_timer = timer;
		detach_timer(timer, true);

		fn = timer->function;
		data = timer->data;

		if (timer->flags & TIMER_IRQSAFE) {
			spin_unlock(&base->lock);
			call_timer_fn(timer, fn, data);
			spin_lock(&base->lock);
		} else {
#if 0
			spin_unlock_irq(&base->lock);
			call_timer_fn(timer, fn, data);
			spin_lock_irq(&base->lock);
#endif
			/*
			 * We are not running via SOFTIRQ.
			 * We are running it from timer interrupt.
			 * Hence do not enable interrupt here.
			 */
			spin_unlock(&base->lock);
			call_timer_fn(timer, fn, data);
			spin_lock(&base->lock);
		}
	}
}

/*
 * By using LVL_CLK_MASK and LVL_CLK_SHIFT, we check different
 * levels with different granularities. With current setting,
 * the 1st level is checked every HZ, the 2rd level is checked
 * every 8HZ, 3rd level with every 64HZ...
 *
 * Eg. if base->clk is 0, then all LVL_DEPTH levels will be checked.
 * If base->clk is 1, only 1st level's bucket will be checked.
 * If base->clk is 8, both 1st and 2rd level's buckets will be checked.
 * If base->clk is 17, then 1st, 2rd, and 3rd level's buckets will be checked.
 *
 * Hats off, elegant code.
 */
static int collect_expired_timers(struct timer_base *base,
				  struct hlist_head *heads)
{
	unsigned long clk = base->clk;
	struct hlist_head *vec;
	int i, levels = 0;
	unsigned int idx;

	for (i = 0; i < LVL_DEPTH; i++) {
		idx = (clk & LVL_MASK) + i * LVL_SIZE;

		if (__test_and_clear_bit(idx, base->pending_map)) {
			vec = base->vectors + idx;
			hlist_move_list(vec, heads++);
			levels++;
		}
		/* Is it time to look at the next level? */
		if (clk & LVL_CLK_MASK)
			break;
		/* Shift clock for the next level granularity */
		clk >>= LVL_CLK_SHIFT;
	}
	return levels;
}

/**
 * run_local_timers - run all expired timers (if any) on this CPU.
 * Called by the local, per-CPU timer interrupt on SMP.
 */
void run_local_timers(void)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);
	struct hlist_head heads[LVL_DEPTH];
	int levels;
	unsigned long flags;

	if (!time_after_eq(jiffies, base->clk))
		return;

	spin_lock_irqsave(&base->lock, flags);

	while (time_after_eq(jiffies, base->clk)) {

		levels = collect_expired_timers(base, heads);
		base->clk++;

		while (levels--)
			expire_timers(base, heads + levels);
	}
	base->running_timer = NULL;

	/* Do NOT enable irq, we're in interrupt */
	spin_unlock_irqrestore(&base->lock, flags);
}

static void process_timeout(unsigned long __data)
{
	wake_up_process((struct task_struct *)__data);
}

/**
 * schedule_timeout - sleep until timeout
 * @timeout: timeout value in jiffies
 *
 * Make the current task sleep until @timeout jiffies have
 * elapsed. The routine will return immediately unless
 * the current task state has been set (see set_current_state()).
 *
 * You can set the task state as follows -
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout jiffies are guaranteed to
 * pass before the routine returns unless the current task is explicitly
 * woken up, (e.g. by wake_up_process())".
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task or the current task is explicitly woken
 * up.
 *
 * The current task state is guaranteed to be TASK_RUNNING when this
 * routine returns.
 *
 * Specifying a @timeout value of %MAX_SCHEDULE_TIMEOUT will schedule
 * the CPU away without a bound on the timeout. In this case the return
 * value will be %MAX_SCHEDULE_TIMEOUT.
 *
 * Returns 0 when the timer has expired otherwise the remaining time in
 * jiffies will be returned.  In all cases the return value is guaranteed
 * to be non-negative.
 */
signed long __sched schedule_timeout(signed long timeout)
{
	struct timer_list timer;
	unsigned long expire;

	switch (timeout)
	{
	case MAX_SCHEDULE_TIMEOUT:
		/*
		 * These two special cases are useful to be comfortable
		 * in the caller. Nothing more. We could take
		 * MAX_SCHEDULE_TIMEOUT from one of the negative value
		 * but I' d like to return a valid offset (>=0) to allow
		 * the caller to do everything it want with the retval.
		 */
		schedule();
		goto out;
	default:
		/*
		 * Another bit of PARANOID. Note that the retval will be
		 * 0 since no piece of kernel is supposed to do a check
		 * for a negative retval of schedule_timeout() (since it
		 * should never happens anyway). You just have the printk()
		 * that will tell you if something is gone wrong and where.
		 */
		if (timeout < 0) {
			printk(KERN_ERR "schedule_timeout: wrong timeout "
				"value %lx\n", timeout);
			dump_stack();
			current->state = TASK_RUNNING;
			goto out;
		}
	}

	expire = timeout + jiffies;

	setup_timer(&timer, process_timeout, (unsigned long)current);
	__mod_timer(&timer, expire, false);
	schedule();
	del_timer_sync(&timer);

	timeout = expire - jiffies;

 out:
	return timeout < 0 ? 0 : timeout;
}

/*
 * We can use __set_current_state() here because schedule_timeout() calls
 * schedule() unconditionally.
 */
signed long __sched schedule_timeout_interruptible(signed long timeout)
{
	__set_current_state(TASK_INTERRUPTIBLE);
	return schedule_timeout(timeout);
}

signed long __sched schedule_timeout_killable(signed long timeout)
{
	__set_current_state(TASK_KILLABLE);
	return schedule_timeout(timeout);
}

signed long __sched schedule_timeout_uninterruptible(signed long timeout)
{
	__set_current_state(TASK_UNINTERRUPTIBLE);
	return schedule_timeout(timeout);
}

static void __init init_timer_cpu(int cpu)
{
	struct timer_base *base;
	int i;

	for (i = 0; i < NR_BASES; i++) {
		base = per_cpu_ptr(&timer_bases[i], cpu);
		base->cpu = cpu;
		spin_lock_init(&base->lock);
		base->clk = jiffies;
	}
}

void __init init_timers(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		init_timer_cpu(cpu);
}

/**
 * msleep - sleep safely even with waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
void msleep(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout)
		timeout = schedule_timeout_uninterruptible(timeout);
}

/**
 * msleep_interruptible - sleep waiting for signals
 * @msecs: Time in milliseconds to sleep for
 */
unsigned long msleep_interruptible(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout)
		timeout = schedule_timeout_interruptible(timeout);
	return jiffies_to_msecs(timeout);
}

SYSCALL_DEFINE2(nanosleep, struct timespec __user *, rqtp,
		struct timespec __user *, rmtp)
{
	struct timespec tu;

	if (copy_from_user(&tu, rqtp, sizeof(tu)))
		return -EFAULT;

	if (!timespec_valid(&tu))
		return -EINVAL;

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(timespec_to_jiffies(&tu));
	set_current_state(TASK_RUNNING);
	return 0;
}
