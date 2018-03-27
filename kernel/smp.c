/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "smp: " fmt

#include <lego/smp.h>
#include <lego/percpu.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>
#include <lego/smpboot.h>

#include <asm/numa.h>

/* Setup number of possible processor ids */
int nr_cpu_ids __read_mostly = NR_CPUS;

DEFINE_PER_CPU(struct task_struct *, idle_threads);

/*
 * Initialize an idle thread for a CPU
 */
static void __init init_idle(int cpu)
{
	struct task_struct *tsk;

	tsk = copy_process(CLONE_VM | CLONE_IDLE_THREAD,
			   0, 0, NULL, 0, cpu_to_node(cpu));
	if (!tsk)
		panic("fail to init idle thread for cpu %d\n", cpu);

	sched_init_idle(tsk, cpu);
	per_cpu(idle_threads, cpu) = tsk;
}

static void __init init_idle_threads(void)
{
	int cpu;

	/* CPU0 */
	BUG_ON(!cpu_online(smp_processor_id()));
	per_cpu(idle_threads, smp_processor_id()) = current;

	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu))
			init_idle(cpu);
	}
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
	int cpu;

	init_idle_threads();

	for_each_present_cpu(cpu) {
		bool boot_this_node = true;

		if (IS_ENABLED(CONFIG_NUMA_USE_ONE_SOCKET)) {
			if (cpu_to_node(cpu) == 0)
				boot_this_node = true;
			else
				boot_this_node = false;
		}

		if (!cpu_online(cpu) && boot_this_node)
			cpu_up(cpu, per_cpu(idle_threads, cpu));
	}
	smp_announce();
}

/*
 * A set of callbacks that each cpu will execute *before* it comes online.
 * It is similar to Linux's cpuhp subsystem, but much simplified.
 */
void cpu_online_callback(unsigned int cpu)
{
	smpcfd_prepare_cpu(cpu);
	smpboot_create_threads(cpu);
	smpboot_unpark_threads(cpu);
}

enum {
	CSD_FLAG_LOCK		= 0x01,
	CSD_FLAG_SYNCHRONOUS	= 0x02,
};

struct call_function_data {
	struct call_single_data	__percpu *csd;
	cpumask_var_t		cpumask;
};

static DEFINE_PER_CPU_SHARED_ALIGNED(struct call_function_data, cfd_data);

static DEFINE_PER_CPU_SHARED_ALIGNED(struct llist_head, call_single_queue);

int smpcfd_prepare_cpu(unsigned int cpu)
{
	struct call_function_data *cfd = &per_cpu(cfd_data, cpu);

	cfd->csd = alloc_percpu(struct call_single_data);
	if (!cfd->csd)
		return -ENOMEM;
	return 0;
}

void __init call_function_init(void)
{
	int i;

	for_each_possible_cpu(i)
		init_llist_head(&per_cpu(call_single_queue, i));

	smpcfd_prepare_cpu(smp_processor_id());
}

/*
 * csd_lock/csd_unlock used to serialize access to per-cpu csd resources
 *
 * For non-synchronous ipi calls the csd can still be in use by the
 * previous function call. For multi-cpu calls its even more interesting
 * as we'll have to ensure no other cpu is observing our csd.
 */
static __always_inline void csd_lock_wait(struct call_single_data *csd)
{
	smp_cond_load_acquire(&csd->flags, !(VAL & CSD_FLAG_LOCK));
}

static __always_inline void csd_lock(struct call_single_data *csd)
{
	csd_lock_wait(csd);
	csd->flags |= CSD_FLAG_LOCK;

	/*
	 * prevent CPU from reordering the above assignment
	 * to ->flags with any subsequent assignments to other
	 * fields of the specified call_single_data structure:
	 */
	smp_wmb();
}

static __always_inline void csd_unlock(struct call_single_data *csd)
{
	WARN_ON(!(csd->flags & CSD_FLAG_LOCK));

	/*
	 * ensure we're all done before releasing data:
	 */
	smp_store_release(&csd->flags, 0);
}

static DEFINE_PER_CPU_SHARED_ALIGNED(struct call_single_data, csd_data);

/*
 * Insert a previously allocated call_single_data element
 * for execution on the given CPU. data must already have
 * ->func, ->info, and ->flags set.
 */
static int generic_exec_single(int cpu, struct call_single_data *csd,
			       smp_call_func_t func, void *info)
{
	if (cpu == smp_processor_id()) {
		unsigned long flags;

		/*
		 * We can unlock early even for the synchronous on-stack case,
		 * since we're doing this from the same CPU..
		 */
		csd_unlock(csd);
		local_irq_save(flags);
		func(info);
		local_irq_restore(flags);
		return 0;
	}


	if ((unsigned)cpu >= nr_cpu_ids || !cpu_online(cpu)) {
		csd_unlock(csd);
		return -ENXIO;
	}

	csd->func = func;
	csd->info = info;

	/*
	 * The list addition should be visible before sending the IPI
	 * handler locks the list to pull the entry off it because of
	 * normal cache coherency rules implied by spinlocks.
	 *
	 * If IPIs can go out of order to the cache coherency protocol
	 * in an architecture, sufficient synchronisation should be added
	 * to arch code to make it appear to obey cache coherency WRT
	 * locking and barrier primitives. Generic code isn't really
	 * equipped to do the right thing...
	 */
	if (llist_add(&csd->llist, &per_cpu(call_single_queue, cpu)))
		arch_send_call_function_single_ipi(cpu);

	return 0;
}

/*
 * smp_call_function_single - Run a function on a specific CPU
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait until function has completed on other CPUs.
 *
 * Returns 0 on success, else a negative status code.
 */
int smp_call_function_single(int cpu, smp_call_func_t func, void *info,
			     int wait)
{
	struct call_single_data *csd;
	struct call_single_data csd_stack = { .flags = CSD_FLAG_LOCK | CSD_FLAG_SYNCHRONOUS };
	int this_cpu;
	int err;

	/*
	 * prevent preemption and reschedule on another processor,
	 * as well as CPU removal
	 */
	this_cpu = get_cpu();

	/*
	 * Can deadlock when called with interrupts disabled.
	 * We allow cpu's that are not yet online though, as no one else can
	 * send smp call function interrupt to this cpu and as such deadlocks
	 * can't happen.
	 */
	WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled());

	csd = &csd_stack;
	if (!wait) {
		csd = this_cpu_ptr(&csd_data);
		csd_lock(csd);
	}

	err = generic_exec_single(cpu, csd, func, info);

	if (wait)
		csd_lock_wait(csd);

	put_cpu();

	return err;
}
/*
 * smp_call_function_any - Run a function on any of the given cpus
 * @mask: The mask of cpus it can run on.
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait until function has completed.
 *
 * Returns 0 on success, else a negative status code (if no cpus were online).
 *
 * Selection preference:
 *	1) current cpu if in @mask
 *	2) any cpu of current node if in @mask
 *	3) any other online cpu in @mask
 */
int smp_call_function_any(const struct cpumask *mask,
			  smp_call_func_t func, void *info, int wait)
{
	unsigned int cpu;
	const struct cpumask *nodemask;
	int ret;

	/* Try for same CPU (cheapest) */
	cpu = get_cpu();
	if (cpumask_test_cpu(cpu, mask))
		goto call;

	/* Try for same node. */
	nodemask = cpumask_of_node(cpu_to_node(cpu));
	for (cpu = cpumask_first_and(nodemask, mask); cpu < nr_cpu_ids;
	     cpu = cpumask_next_and(cpu, nodemask, mask)) {
		if (cpu_online(cpu))
			goto call;
	}

	/* Any online will do: smp_call_function_single handles nr_cpu_ids. */
	cpu = cpumask_any_and(mask, cpu_online_mask);
call:
	ret = smp_call_function_single(cpu, func, info, wait);
	put_cpu();
	return ret;
}
/**
 * smp_call_function_many(): Run a function on a set of other CPUs.
 * @mask: The set of cpus to run on (only runs on online subset).
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 *
 * If @wait is true, then returns once @func has returned.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler. Preemption
 * must be disabled when calling this function.
 */
void smp_call_function_many(const struct cpumask *mask,
			    smp_call_func_t func, void *info, bool wait)
{
	struct call_function_data *cfd;
	int cpu, next_cpu, this_cpu = smp_processor_id();

	/*
	 * Can deadlock when called with interrupts disabled.
	 * We allow cpu's that are not yet online though, as no one else can
	 * send smp call function interrupt to this cpu and as such deadlocks
	 * can't happen.
	 */
	WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled());

	/* Try to fastpath.  So, what's a CPU they want? Ignoring this one. */
	cpu = cpumask_first_and(mask, cpu_online_mask);
	if (cpu == this_cpu)
		cpu = cpumask_next_and(cpu, mask, cpu_online_mask);

	/* No online cpus?  We're done. */
	if (cpu >= nr_cpu_ids)
		return;

	/* Do we have another CPU which isn't us? */
	next_cpu = cpumask_next_and(cpu, mask, cpu_online_mask);
	if (next_cpu == this_cpu)
		next_cpu = cpumask_next_and(next_cpu, mask, cpu_online_mask);

	/* Fastpath: do that cpu by itself. */
	if (next_cpu >= nr_cpu_ids) {
		smp_call_function_single(cpu, func, info, wait);
		return;
	}

	cfd = this_cpu_ptr(&cfd_data);

	cpumask_and(cfd->cpumask, mask, cpu_online_mask);
	cpumask_clear_cpu(this_cpu, cfd->cpumask);

	/* Some callers race with other cpus changing the passed mask */
	if (unlikely(!cpumask_weight(cfd->cpumask)))
		return;

	for_each_cpu(cpu, cfd->cpumask) {
		struct call_single_data *csd = per_cpu_ptr(cfd->csd, cpu);

		csd_lock(csd);
		if (wait)
			csd->flags |= CSD_FLAG_SYNCHRONOUS;
		csd->func = func;
		csd->info = info;
		llist_add(&csd->llist, &per_cpu(call_single_queue, cpu));
	}

	/* Send a message to all CPUs in the map */
	arch_send_call_function_ipi_mask(cfd->cpumask);

	if (wait) {
		for_each_cpu(cpu, cfd->cpumask) {
			struct call_single_data *csd;

			csd = per_cpu_ptr(cfd->csd, cpu);
			csd_lock_wait(csd);
		}
	}
}

/**
 * smp_call_function(): Run a function on all other CPUs.
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 *
 * Returns 0.
 *
 * If @wait is true, then returns once @func has returned; otherwise
 * it returns just before the target cpu calls @func.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler.
 */
int smp_call_function(smp_call_func_t func, void *info, int wait)
{
	preempt_disable();
	smp_call_function_many(cpu_online_mask, func, info, wait);
	preempt_enable();

	return 0;
}

/**
 * flush_smp_call_function_queue - Flush pending smp-call-function callbacks
 *
 * @warn_cpu_offline: If set to 'true', warn if callbacks were queued on an
 *		      offline CPU. Skip this check if set to 'false'.
 *
 * Flush any pending smp-call-function callbacks queued on this CPU. This is
 * invoked by the generic IPI handler, as well as by a CPU about to go offline,
 * to ensure that all pending IPI callbacks are run before it goes completely
 * offline.
 *
 * Loop through the call_single_queue and run all the queued callbacks.
 * Must be called with interrupts disabled.
 */
static void flush_smp_call_function_queue(bool warn_cpu_offline)
{
	struct llist_head *head;
	struct llist_node *entry;
	struct call_single_data *csd, *csd_next;
	static bool warned;

	WARN_ON(!irqs_disabled());

	head = this_cpu_ptr(&call_single_queue);
	entry = llist_del_all(head);
	entry = llist_reverse_order(entry);

	/* There shouldn't be any pending callbacks on an offline CPU. */
	if (unlikely(warn_cpu_offline && !cpu_online(smp_processor_id()) &&
		     !warned && !llist_empty(head))) {
		warned = true;
		WARN(1, "IPI on offline CPU %d\n", smp_processor_id());

		/*
		 * We don't have to use the _safe() variant here
		 * because we are not invoking the IPI handlers yet.
		 */
		llist_for_each_entry(csd, entry, llist)
			pr_warn("IPI callback %pS sent to offline CPU\n",
				csd->func);
	}

	llist_for_each_entry_safe(csd, csd_next, entry, llist) {
		smp_call_func_t func = csd->func;
		void *info = csd->info;

		/* Do we wait until *after* callback? */
		if (csd->flags & CSD_FLAG_SYNCHRONOUS) {
			func(info);
			csd_unlock(csd);
		} else {
			csd_unlock(csd);
			func(info);
		}
	}
}

/**
 * generic_smp_call_function_single_interrupt - Execute SMP IPI callbacks
 *
 * Invoked by arch to handle an IPI for call function single.
 * Must be called with interrupts disabled.
 */
void generic_smp_call_function_single_interrupt(void)
{
	flush_smp_call_function_queue(true);
}
