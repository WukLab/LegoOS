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
#include <lego/cpumask.h>
#include <lego/kallsyms.h>
#include <asm/irq_regs.h>

/*
 * The mechanism of heatmap is pretty simple:
 * on each timer interrupt, we check and interrupted IP address,
 * and increment its counter.
 *
 * This version use one global counter array, so it will affect runtime
 * performance a lot in a SMP system. Use with caution.
 */

struct profile_hit {
	u32 pc, hits;
};

#define default_prof_shift	2

static atomic_t *prof_buffer;
static unsigned long prof_buffer_bytes;
static unsigned long prof_len, prof_shift;

int prof_on __read_mostly;

int profile_heatmap_init(void)
{
	prof_on = CPU_PROFILING;
	prof_shift = default_prof_shift;

	/* only text is profiled */
	prof_len = (__etext - __stext) >> prof_shift;
	prof_buffer_bytes = prof_len * sizeof(atomic_t);

	prof_buffer = kzalloc(prof_buffer_bytes, GFP_KERNEL);
	if (!prof_buffer)
		return -ENOMEM;

	pr_info("Kernel cpu_profiling enabled (shift: %ld, buffer_bytes: %lu)\n",
		prof_shift, prof_buffer_bytes);

	return 0;
}

#if 1
/* non-SMP version */
#define profile_flip_buffers()		do { } while (0)
#define profile_discard_flip_buffers()	do { } while (0)

static void do_profile_hits(int type, void *__pc, unsigned int nr_hits)
{
	unsigned long pc;
	pc = ((unsigned long)__pc - (unsigned long)__stext) >> prof_shift;
	atomic_add(nr_hits, &prof_buffer[min(pc, prof_len - 1)]);
}
#endif

void profile_hits(int type, void *__pc, unsigned int nr_hits)
{
	if (!prof_buffer)
		return;
	do_profile_hits(type, __pc, nr_hits);
}

void profile_tick(int type)
{
	struct pt_regs *regs = get_irq_regs();

	if (!user_mode(regs))
		profile_hit(type, (void *)GET_IP(regs));
}

struct readprofile {
	unsigned long addr;
	int nr;
};

static int readprofile_sort(const void *a, const void *b)
{
	const struct readprofile *sa = a, *sb = b;

	if (sa->nr < sb->nr)
		return 1;
	return -1;
}

/*
 * Simple readprofile
 * Print top @nr entries in heatmap
 */
void print_profile_heatmap_nr(int nr)
{
	atomic_t *buf;
	struct readprofile *profile, *p;
	unsigned long sym_start, addr_prof;
	int i, idx_counter, idx_profile;
	s64 total_nr = 0;

	if (!prof_buffer || !prof_on)
		return;

	/* Copy counters */
	buf = kmalloc(prof_buffer_bytes, GFP_KERNEL);
	if (!buf)
		return;
	memcpy(buf, prof_buffer, prof_buffer_bytes);

	profile = kzalloc(sizeof(*profile) * prof_len, GFP_KERNEL);
	if (!profile) {
		kfree(buf);
		return;
	}

	/* Aggregate counters by symbols */
	for (idx_counter = 0; idx_counter < prof_len; idx_counter++) {
		if (!atomic_read(&buf[idx_counter]))
			continue;

		addr_prof = (idx_counter << prof_shift) + (unsigned long)__stext;
		sym_start = get_symbol_start_addr(addr_prof);

		/*
		 * sym_start may does not map to specific slots
		 * if the prof_shift is too large. So this might
		 * aggregate multiple functions into one.
		 */
		idx_profile = (sym_start - (unsigned long)__stext) >> prof_shift;
		p = &profile[idx_profile];

		p->nr += atomic_read(&buf[idx_counter]);
		total_nr += atomic_read(&buf[idx_counter]);

		/*
		 * If merge does happen, merge the high address one
		 * into the low address one. But let user know.
		 */
		if (p->addr) {
			if (unlikely(p->addr != sym_start)) {
				pr_info("readprofile: merge %pf into %pf\n",
					(void *)sym_start, (void *)p->addr);
			}
		}
		p->addr = sym_start;
	}

	sort(profile, prof_len, sizeof(*profile), readprofile_sort, NULL);

	pr_info("\n");
	pr_info("Kernel Heatmap (top #%lu)\n", min((unsigned long)nr, prof_len));
	pr_info("         Address              Function          NR          %%\n");
	pr_info("----------------  --------------------  ----------  ---------\n");
	for (i = 0; i < nr && i < prof_len; i++) {
		u64 p_i, p_re;
		char p_re_buf[8];
		char p_sym[20];

		p = &profile[i];
		if (!p->nr)
			continue;

		p_i = div64_u64_rem(p->nr * 100UL, total_nr, &p_re);
		scnprintf(p_re_buf, 3, "%Lu", p_re);
		scnprintf(p_sym, 20, "%pf", (void *)p->addr);

		printk("%lx  %20s  %10d  %6Ld.%s\n",
			p->addr, p_sym, p->nr, p_i, p_re_buf);
	}
	pr_info("----------------  --------------------  ----------  ---------\n");
	pr_info("                                        %10Lu     100.00\n", total_nr);
	pr_info("\n");

	kfree(profile);
	kfree(buf);
}
