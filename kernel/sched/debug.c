/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/pid.h>
#include <lego/time.h>
#include <lego/mutex.h>
#include <lego/sched.h>
#include <lego/sched_rt.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/jiffies.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>
#include <lego/ktime.h>
#include <lego/utsname.h>
#include <lego/seq_file.h>

#include "sched.h"

static DEFINE_SPINLOCK(sched_debug_lock);

#ifdef CONFIG_COMP_PROCESSOR
/*
 * This allows printing both to /proc/sched_debug and
 * to the console
 */
#define SEQ_printf(m, x...)			\
 do {						\
	if (m)					\
		seq_printf(m, x);		\
	else					\
		printk(x);			\
 } while (0)

#define SEQ_printf_cont(m, x...)		\
 do {						\
	if (m)					\
		seq_printf(m, x);		\
	else					\
		pr_cont(x);			\
 } while (0)
#else
/* Memory Component does not have seq_file */
#define SEQ_printf(m, x...)		printk(x)
#define SEQ_printf_cont(m, x...)	pr_cont(x)
#endif

/*
 * Ease the printing of nsec fields:
 */
static long long nsec_high(unsigned long long nsec)
{
	if ((long long)nsec < 0) {
		nsec = -nsec;
		do_div(nsec, 1000000);
		return -nsec;
	}
	do_div(nsec, 1000000);

	return nsec;
}

static unsigned long nsec_low(unsigned long long nsec)
{
	if ((long long)nsec < 0)
		nsec = -nsec;

	return do_div(nsec, 1000000);
}

#define SPLIT_NS(x) nsec_high(x), nsec_low(x)

static void
print_task(struct seq_file *m, struct rq *rq, struct task_struct *p)
{
	if (rq->curr == p)
		SEQ_printf(m, "R");
	else
		SEQ_printf(m, " ");

	SEQ_printf_cont(m, "%15s %5d %9Ld.%06ld %9Ld %6Ld %7Ld %5d ",
		p->comm, p->pid,
		SPLIT_NS(p->se.vruntime),
		(long long)(p->nvcsw + p->nivcsw),
		(long long)p->nvcsw, (long long)p->nivcsw,
		p->prio);

	SEQ_printf_cont(m, "%9Ld.%06ld %9Ld.%06ld %9Ld.%06ld %10lu\n",
		SPLIT_NS(0),
		SPLIT_NS(p->se.sum_exec_runtime),
		SPLIT_NS(0),
		p->utime);
}

static void print_rq(struct seq_file *m, struct rq *rq, int rq_cpu)
{
	struct task_struct *g, *p;

	SEQ_printf(m,
	"runnable tasks:\n");

	SEQ_printf(m,
	"            task   PID         tree-key  switches  nvcsw  nivcsw  prio"
	"        wait-time         sum-exec        sum-sleep     utime\n");

	SEQ_printf(m,
	"-----------------------------------------------------------"
	"------------------------------------------------------------------------\n");

	for_each_process_thread(g, p) {
		if (task_cpu(p) != rq_cpu)
			continue;

		print_task(m, rq, p);
	}
}

void print_cfs_rq(struct seq_file *m, int cpu, struct cfs_rq *cfs_rq)
{
	SEQ_printf(m, "cfs_rq[%d]:\n", cpu);
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "exec_clock",
			SPLIT_NS(cfs_rq->exec_clock));

	SEQ_printf(m, "  .%-30s: %d\n", "nr_running", cfs_rq->nr_running);
	SEQ_printf(m, "  .%-30s: %ld\n", "load", cfs_rq->load.weight);
}

void print_cfs_stats(struct seq_file *m, int cpu)
{
	struct cfs_rq *cfs_rq = &cpu_rq(cpu)->cfs;

	print_cfs_rq(m, cpu, cfs_rq);
}

void print_rt_rq(struct seq_file *m, int cpu, struct rt_rq *rt_rq)
{
	SEQ_printf(m, "rt_rq[%d]:\n", cpu);

#define P(x) \
	SEQ_printf(m, "  .%-30s: %Ld\n", #x, (long long)(rt_rq->x))
#define PN(x) \
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", #x, SPLIT_NS(rt_rq->x))

	P(rt_nr_running);
	P(rt_throttled);
	PN(rt_time);
	PN(rt_runtime);

#undef PN
#undef P
}

void print_rt_stats(struct seq_file *m, int cpu)
{
	struct rt_rq *rt_rq = &cpu_rq(cpu)->rt;

	print_rt_rq(m, cpu, rt_rq);
}

void print_dl_stats(struct seq_file *m, int cpu)
{

}

static void print_cpu(struct seq_file *m, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;
	unsigned int freq = cpu_khz ? : 1;

	SEQ_printf(m, "cpu#%d, %u.%03u MHz\n",
		   cpu, freq / 1000, (freq % 1000));

#define P(x)								\
do {									\
	if (sizeof(rq->x) == 4)						\
		SEQ_printf(m, "  .%-30s: %ld\n", #x, (long)(rq->x));	\
	else								\
		SEQ_printf(m, "  .%-30s: %Ld\n", #x, (long long)(rq->x));\
} while (0)

#define PN(x) \
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", #x, SPLIT_NS(rq->x))

	P(nr_running);
	SEQ_printf(m, "  .%-30s: %lu\n", "load",
		   rq->load.weight);
	P(nr_switches);
	P(nr_load_updates);
	P(nr_uninterruptible);
	SEQ_printf(m, "  .%-30s: %ld\n", "curr->pid", (long)(rq->curr->pid));
	PN(clock);
	PN(clock_task);
#undef P
#undef PN

	spin_lock_irqsave(&sched_debug_lock, flags);
	print_cfs_stats(m, cpu);
	print_rt_stats(m, cpu);
	print_dl_stats(m, cpu);

	print_rq(m, rq, cpu);
	spin_unlock_irqrestore(&sched_debug_lock, flags);
	SEQ_printf(m, "\n");
}

static void sched_debug_header(struct seq_file *m)
{
	u64 ktime, sched_clk;
	unsigned long flags;

	local_irq_save(flags);
	ktime = ktime_to_ns(ktime_get());
	sched_clk = sched_clock();
	local_irq_restore(flags);

	SEQ_printf(m, "Sched Debug Version: v0.11\n");

#define P(x) \
	SEQ_printf(m, "%-40s: %Ld\n", #x, (long long)(x))
#define PN(x) \
	SEQ_printf(m, "%-40s: %Ld.%06ld\n", #x, SPLIT_NS(x))
	PN(ktime);
	PN(sched_clk);
	P(jiffies);
#undef PN
#undef P

	SEQ_printf(m, "\n");
	SEQ_printf(m, "sysctl_sched\n");

#define P(x) \
	SEQ_printf(m, "  .%-40s: %Ld\n", #x, (long long)(x))
#define PN(x) \
	SEQ_printf(m, "  .%-40s: %Ld.%06ld\n", #x, SPLIT_NS(x))
	PN(sysctl_sched_latency);
	PN(sysctl_sched_min_granularity);
	PN(sysctl_sched_wakeup_granularity);
	P(sysctl_sched_child_runs_first);
	P(sysctl_sched_rr_timeslice);
#undef PN
#undef P
	SEQ_printf(m, "\n");
}

static void dump_cpumasks(void)
{
	char buf[64];

	sprintf(buf, "Online CPU: %*pbl\n", nr_cpu_ids, cpu_online_mask);
	pr_debug("%s", buf);
	sprintf(buf, "Active CPU: %*pbl\n", nr_cpu_ids, cpu_active_mask);
	pr_debug("%s", buf);
}

/*
 * When this function is called from panic()
 * All other CPUs have been taken down already.
 * So use present cpumask instead. But print the online/active
 * cpumask as well.
 */
void sysrq_sched_debug_show(void)
{
	int cpu;

	dump_cpumasks();
	for_each_present_cpu(cpu)
		print_cpu(NULL, cpu);

}

static const char stat_nam[] = TASK_STATE_TO_CHAR_STR;

void sched_show_task(struct task_struct *p)
{
	unsigned long free = 0;
	unsigned long state = p->state;

	if (state)
		state = __ffs(state) + 1;
	printk(KERN_INFO "%-15.15s %c(%#lx)", p->comm,
		state < sizeof(stat_nam) - 1 ? stat_nam[state] : '?', state);
	if (state == TASK_RUNNING)
		printk(KERN_CONT "  running task    ");

	printk(KERN_CONT "%5lu %5d %6d 0x%08lx\n", free,
		p->pid, p->real_parent->pid,
		(unsigned long)task_thread_info(p)->flags);
}

void show_state_filter(unsigned long state_filter, bool print_rq)
{
	struct task_struct *g, *p;

	sched_debug_header(NULL);

#if BITS_PER_LONG == 32
	printk(KERN_INFO
		"  task                PC stack   pid father\n");
#else
	printk(KERN_INFO
		"  task                        PC stack   pid father\n");
#endif
	spin_lock(&tasklist_lock);
	for_each_process_thread(g, p) {
		if (!state_filter || (p->state & state_filter))
			sched_show_task(p);
	}
	if (!state_filter && print_rq)
		sysrq_sched_debug_show();
	spin_unlock(&tasklist_lock);
}
