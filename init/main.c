/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/pid.h>
#include <lego/smp.h>
#include <lego/bug.h>
#include <lego/tty.h>
#include <lego/irq.h>
#include <lego/pci.h>
#include <lego/net.h>
#include <lego/init.h>
#include <lego/list.h>
#include <lego/slab.h>
#include <lego/time.h>
#include <lego/wait.h>
#include <lego/timex.h>
#include <lego/futex.h>
#include <lego/timer.h>
#include <lego/delay.h>
#include <lego/sched.h>
#include <lego/memory.h>
#include <lego/string.h>
#include <lego/atomic.h>
#include <lego/kernel.h>
#include <lego/profile.h>
#include <lego/extable.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/spinlock.h>
#include <lego/irqdomain.h>
#include <lego/fit_ibapi.h>
#include <lego/radixtree.h>
#include <lego/workqueue.h>
#include <lego/completion.h>
#include <lego/stop_machine.h>

#include <lego/comp_memory.h>
#include <lego/comp_common.h>
#include <processor/processor.h>

#include <asm/io.h>
#include <asm/asm.h>
#include <asm/page.h>
#include <asm/numa.h>
#include <asm/traps.h>
#include <asm/setup.h>
#include <asm/fpu/internal.h>

enum system_states system_state __read_mostly;

/* Screen information used by kernel */
struct screen_info screen_info;

/* Builtin command line from kconfig */
#ifdef CONFIG_CMDLINE_BOOL
static char __initdata builtin_cmdline[COMMAND_LINE_SIZE] = CONFIG_CMDLINE;
#endif

/* Untouched command line saved by head, passed from boot loader */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/* Concatenated command line from boot and builtin */
char command_line[COMMAND_LINE_SIZE];

/* Setup configured maximum number of CPUs to activate */
unsigned int setup_max_cpus = NR_CPUS;

extern void calibrate_delay(void);

/* Defined in linker scripts */
extern const struct obs_kernel_param __sinitsetup[], __einitsetup[];

static int __init parse_kernel_param(char *param, char *val)
{
	const struct obs_kernel_param *p;

	for (p = __sinitsetup; p < __einitsetup; p++) {
		if (parameq(param, p->str)) {
			if (p->setup_func(val) != 0) {
				pr_warn("Malformed option '%s'\n", param);
				return -ENOENT;
			}
		}
	}
	return 0;
}

static void inline setup_nr_cpu_ids(void)
{
	nr_cpu_ids = find_last_bit(cpumask_bits(cpu_possible_mask), NR_CPUS) + 1;
}

static __initdata DEFINE_COMPLETION(kthreadd_done);

/*
 * This is our first kernel thread (pid 1),
 */
static int kernel_init(void *unused)
{
	/* Wait until kthreadd is all set-up. */
	wait_for_completion(&kthreadd_done);

	/*
	 * init can run on any cpu.
	 *
	 * NOTE: we get the cpus_allowed mask from parent, which
	 * is the init_task, whose cpus_allowed will be cpu0 & nr_cpu_allowed=1.
	 * That was set when it calls sched_init, which will further
	 * call the sched_init_idle to make itself an idle thread.
	 */
	set_cpus_allowed_ptr(current, cpu_possible_mask);

	set_task_comm(current, "kernel_init");

	/*
	 * Create [migration/%d] threads
	 * (highest-priority stop class)
	 */
	cpu_stop_init();

	init_workqueues();

	/*
	 * Scan the PCI bus and build core PCI data structures.
	 * Then we initialize all the devices (IB, Ethernet etc)
	 */
	pci_subsys_init();
	device_init();
	dump_irq_domain_list();

#if defined(CONFIG_INFINIBAND) && defined(CONFIG_FIT)
	init_socket();
	kthread_run(lego_ib_init, NULL, "ib-initd");

	/* wait until ib finished initialization */
	wait_for_completion(&ib_init_done);

	test_socket();
#endif

	/* Final step towards a running component.. */
	manager_init();

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	BUG();
	return 0;
}

static void rest_init(void)
{
	int pid;

#ifdef CONFIG_COMP_PROCESSOR
	/*
	 * For backward compatibility:
	 *	Open STDIN, STDOUT, STDERR by default.
	 * Later on, every child process will inherit
	 * these 3 open files:
	 */
	open_stdio_files();
#endif

	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	kernel_thread(kernel_init, NULL, 0);

	pid = kernel_thread(kthreadd, NULL, 0);
	kthreadd_task = find_task_by_pid(pid);
	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving (the preempt
	 * count must be 1 here):
	 */
	setup_init_idleclass(current);
	schedule_preempt_disabled();

	/* Call into cpu_idle with preempt disabled */
	cpu_idle();
}

void __init patch_init_task(void);

asmlinkage void __init start_kernel(void)
{
	local_irq_disable();

	patch_init_task();
	setup_task_stack_end_magic(&init_task);
	mm_init_cpumask(&init_mm);

	boot_cpumask_init();

	/* Prepare output first */
	tty_init();
	pr_info("%s", lego_banner);

#ifdef CONFIG_CMDLINE_BOOL
	if (builtin_cmdline[0]) {
		/* append boot loader cmdline to builtin */
		strlcat(builtin_cmdline, " ", COMMAND_LINE_SIZE);
		strlcat(builtin_cmdline, boot_command_line, COMMAND_LINE_SIZE);
		strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
	}
#endif
	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	pr_info("Command line: %s\n", command_line);

	/* Things to be done before parsing cmdline */
	early_setup_arch();

	/* Parse setup parameters */
	parse_args(command_line, parse_kernel_param);

	/* Architecture-Specific Initialization */
	setup_arch();
	setup_nr_cpu_ids();
	setup_nr_node_ids();
	setup_per_cpu_areas();

	/*
	 * Init CPU0
	 * cpu_init() will use smp_processor_id(), which
	 * MUST come after setting up per-cpu areas
	 */
	cpu_init();

	/* Allocate pid mapping array */
	pid_init();
	fork_init();

	sort_main_extable();

	futex_init();

	/*
	 * Processor and memory manager both need
	 * large chunk of contiguous physical memory.
	 * Do this prior buddy is up.
	 */
	processor_manager_early_init();
	memory_manager_early_init();

	/*
	 * JUST A NOTE:
	 * If we have any large bootmem allocations later (e.g. printk logbuf),
	 * they should go right before memory_init(), because memory_init()
	 * will reserve the reserved memblock, and free the free memblock
	 * to buddy allocator. No more large allocations will be possible.
	 */

	/*
	 * Build all memory managment data structures,
	 * buddy allocator is avaiable afterwards:
	 */
	memory_init();

	/*
	 * IRQ subsystem is the first user of radix tree
	 * If we have something come up, good luck remmebering this..
	 */
	radix_tree_init();
	irq_init();

	/*
	 * First init timer data structures.
	 * Then we need to init timekeeping subsystem.
	 * At last, we register better clocksources and notify timekeeping subsystem.
	 * and new clockevent devices will be installed.
	 *
	 * Do note that after time_init(), our clocksource is final (x86 is tsc)
	 * But our clockevent device is not. After time_init() it should be hpet,
	 * but later on it will switch to local-APIC timer clockevent.
	 *
	 * Do note that clocksource is used to *read the time*. However clockevent device
	 * is used to *fire timer interrupt*, which will call update_wall_time() to
	 * let clocksource subsystem use current clocksource to update wall time!
	 *
	 * Clockevent and clocksource are two different data structures.
	 * But they can be the same device. (Well, normally is different I think)
	 */
	init_timers();
	timekeeping_init();
	register_refined_jiffies(CLOCK_TICK_RATE);
	time_init();
	calibrate_delay();

	/*
	 * Set up the scheduler prior starting any interrupts,
	 * such as timer interrupt. Full topology setup happens
	 * at smp_init(), but meanwhile we still have a functioning
	 * scheduler:
	 */
	sched_init();
	call_function_init();

	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();

	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();

	/*
	 * Boot all possible CPUs
	 */
	smp_prepare_cpus(setup_max_cpus);
	local_irq_enable();
	smp_init();

	/*
	 * For Lego, system is not fully running
	 * until smp is initialized.
	 */
	system_state = SYSTEM_RUNNING;

	boot_time_profile();
	profile_heatmap_init();

	/* STOP! WE ARE ALIVE NOW */
	rest_init();
}
