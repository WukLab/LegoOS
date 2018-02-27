/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/jiffies.h>
#include <lego/stat.h>
#include <lego/sched.h>
#include <lego/slab.h>
#include <lego/files.h>
#include <lego/seq_file.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>
#include <lego/timekeeping.h>

#include <asm/tsc.h>
#include <asm/processor.h>

/*
 *	Get CPU information for use by the procfs.
 */
static void show_cpuinfo_core(struct seq_file *m, struct cpu_info *c,
			      unsigned int cpu)
{
#ifdef CONFIG_SMP
	seq_printf(m, "physical id\t: %d\n", c->phys_proc_id);
	seq_printf(m, "siblings\t: N/A\n");
	seq_printf(m, "core id\t\t: %d\n", c->cpu_core_id);
	seq_printf(m, "cpu cores\t: %d\n", c->booted_cores);
	seq_printf(m, "apicid\t\t: %d\n", c->apicid);
	seq_printf(m, "initial apicid\t: %d\n", c->initial_apicid);
#endif
}

static void show_cpuinfo_misc(struct seq_file *m, struct cpu_info *c)
{
	seq_printf(m,
		   "fpu\t\t: yes\n"
		   "fpu_exception\t: yes\n"
		   "cpuid level\t: %d\n"
		   "wp\t\t: yes\n",
		   c->cpuid_level);
}

static int show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpu_info *c = v;
	unsigned int cpu;
	int i;

	cpu = c->cpu_index;
	seq_printf(m, "processor\t: %u\n"
		   "vendor_id\t: %s\n"
		   "cpu family\t: %d\n"
		   "model\t\t: %u\n"
		   "model name\t: %s\n",
		   cpu,
		   c->x86_vendor_id[0] ? c->x86_vendor_id : "unknown",
		   c->x86,
		   c->x86_model,
		   c->x86_model_id[0] ? c->x86_model_id : "unknown");

	if (c->x86_mask || c->cpuid_level >= 0)
		seq_printf(m, "stepping\t: %d\n", c->x86_mask);
	else
		seq_puts(m, "stepping\t: unknown\n");
	if (c->microcode)
		seq_printf(m, "microcode\t: 0x%x\n", c->microcode);

	if (cpu_has(X86_FEATURE_TSC)) {
		seq_printf(m, "cpu MHz\t\t: %u.%03u\n",
			   cpu_khz / 1000, (cpu_khz % 1000));
	}

	/* Cache size */
	if (c->x86_cache_size >= 0)
		seq_printf(m, "cache size\t: %d KB\n", c->x86_cache_size);

	show_cpuinfo_core(m, c, cpu);
	show_cpuinfo_misc(m, c);

	seq_puts(m, "flags\t\t:");
	for (i = 0; i < 32*NCAPINTS; i++)
		if (cpu_has(i) && x86_cap_flags[i] != NULL)
			seq_printf(m, " %s", x86_cap_flags[i]);

	seq_puts(m, "\nbugs\t\t:");
	for (i = 0; i < 32*NBUGINTS; i++) {
		unsigned int bug_bit = 32*NCAPINTS + i;

		if (cpu_has_bug(c, bug_bit) && x86_bug_flags[i])
			seq_printf(m, " %s", x86_bug_flags[i]);
	}

	seq_printf(m, "\nbogomips\t: %lu.%02lu\n",
		   c->loops_per_jiffy/(500000/HZ),
		   (c->loops_per_jiffy/(5000/HZ)) % 100);

#ifdef CONFIG_X86_64
	if (c->x86_tlbsize > 0)
		seq_printf(m, "TLB size\t: %d 4K pages\n", c->x86_tlbsize);
#endif
	seq_printf(m, "clflush size\t: %u\n", c->x86_clflush_size);
	seq_printf(m, "cache_alignment\t: %d\n", c->x86_cache_alignment);
	seq_printf(m, "address sizes\t: %u bits physical, %u bits virtual\n",
		   c->x86_phys_bits, c->x86_virt_bits);

	seq_puts(m, "power management:");
	for (i = 0; i < 32; i++) {
		if (c->x86_power & (1 << i)) {
			if (i < ARRAY_SIZE(x86_power_flags) &&
			    x86_power_flags[i])
				seq_printf(m, "%s%s",
					   x86_power_flags[i][0] ? " " : "",
					   x86_power_flags[i]);
			else
				seq_printf(m, " [%d]", i);
		}
	}

	seq_puts(m, "\n\n");

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	*pos = cpumask_next(*pos - 1, cpu_online_mask);
	/*
	 * TODO:
	 * only print 1
	 */
	if ((*pos) < 1)
		return &cpu_data(*pos);
	return NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

static const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_cpuinfo,
};

static int cpuinfo_open(struct file *file)
{
	return seq_open(file, &cpuinfo_op);
}

struct file_operations proc_cpuinfo_ops = {
	.open		= cpuinfo_open,
	.read		= seq_read,
	.release	= seq_release,
};
