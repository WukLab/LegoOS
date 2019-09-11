/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SCHED_H_
#define _LEGO_SCHED_H_

#include <lego/mm.h>
#include <lego/cred.h>
#include <lego/files.h>
#include <lego/llist.h>
#include <lego/magic.h>
#include <lego/signal.h>
#include <lego/rbtree.h>
#include <lego/strace.h>
#include <lego/preempt.h>
#include <lego/sched_prio.h>

#include <asm/tsc.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <asm/ucontext.h>
#include <asm/processor.h>
#include <asm/switch_to.h>
#include <asm/thread_info.h>

#include <processor/processor_types.h>

/*
 * Scheduling policies
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5

/*
 * Clone Flags:
 */
#define CSIGNAL			0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM		0x00000100	/* set if VM shared between processes */
#define CLONE_FS		0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES		0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND		0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE		0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK		0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT		0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD		0x00010000	/* Same thread group? */
#define CLONE_NEWNS		0x00020000	/* New mount namespace group */
#define CLONE_SYSVSEM		0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS		0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

/*
 * Lego Specific clone flags:
 */
#define CLONE_IDLE_THREAD	0x100000000	/* set if we want to clone an idle thread */
#define CLONE_GLOBAL_THREAD	0x200000000	/* set if it is global */

/*
 * task->state and task->exit_state
 *
 * We have two separate sets of flags: task->state
 * is about runnability, while task->exit_state are
 * about the task exiting. Confusing, but this way
 * modifying one set can't modify the other one by
 * mistake.
 */
#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define __TASK_STOPPED		4
#define __TASK_TRACED		8
/* in tsk->exit_state */
#define EXIT_DEAD		16
#define EXIT_ZOMBIE		32
#define EXIT_TRACE		(EXIT_ZOMBIE | EXIT_DEAD)
/* in tsk->state again */
#define TASK_DEAD		64
#define TASK_WAKEKILL		128
#define TASK_WAKING		256
#define TASK_PARKED		512
#define TASK_NOLOAD		1024
#define TASK_NEW		2048
#define TASK_CHECKPOINTING	4096
#define TASK_STATE_MAX		8192

#define TASK_STATE_TO_CHAR_STR		"RSDTtXZxKWPNnC"

extern char ___assert_task_state[1 - 2*!!(
		sizeof(TASK_STATE_TO_CHAR_STR)-1 != ilog2(TASK_STATE_MAX)+1)];

/* Convenience macros for the sake of set_current_state: */
#define TASK_KILLABLE			(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED			(TASK_WAKEKILL | __TASK_TRACED)

#define TASK_IDLE			(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

/* Convenience macros for the sake of wake_up */
#define TASK_NORMAL		(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
#define TASK_ALL		(TASK_NORMAL | __TASK_STOPPED | __TASK_TRACED)

#define task_is_traced(task)		((task->state & __TASK_TRACED) != 0)

#define task_is_stopped(task)		((task->state & __TASK_STOPPED) != 0)

#define task_is_stopped_or_traced(task)	((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)

#define task_contributes_to_load(task)	((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
					 (task->flags & PF_FROZEN) == 0 && \
					 (task->state & TASK_NOLOAD) == 0)

/*
 * set_current_state() includes a barrier so that the write of current->state
 * is correctly serialised wrt the caller's subsequent test of whether to
 * actually sleep:
 *
 *   for (;;) {
 *	set_current_state(TASK_UNINTERRUPTIBLE);
 *	if (!need_sleep)
 *		break;
 *
 *	schedule();
 *   }
 *   __set_current_state(TASK_RUNNING);
 *
 * If the caller does not need such serialisation (because, for instance, the
 * condition test and condition change and wakeup are under the same lock) then
 * use __set_current_state().
 *
 * The above is typically ordered against the wakeup, which does:
 *
 *	need_sleep = false;
 *	wake_up_state(p, TASK_UNINTERRUPTIBLE);
 *
 * Where wake_up_state() (and all other wakeup primitives) imply enough
 * barriers to order the store of the variable against wakeup.
 *
 * Wakeup will do: if (@state & p->state) p->state = TASK_RUNNING, that is,
 * once it observes the TASK_UNINTERRUPTIBLE store the waking CPU can issue a
 * TASK_RUNNING store which can collide with __set_current_state(TASK_RUNNING).
 *
 * This is obviously fine, since they both store the exact same value.
 *
 * Also see the comments of try_to_wake_up().
 */
#define __set_current_state(state_value)		\
do {							\
	current->state = (state_value);			\
} while (0)

#define set_current_state(state_value)			\
do {							\
	smp_store_mb(current->state, (state_value));	\
} while (0)

#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define set_task_state(tsk, state_value)		\
	smp_store_mb((tsk)->state, (state_value))

/*
 * task->flags
 */
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_EXITING		0x00000004	/* getting shut down */
#define PF_EXITPIDONE		0x00000008	/* pi exit done on shut down */
#define PF_VCPU			0x00000010	/* I'm a virtual CPU */
#define PF_WQ_WORKER		0x00000020	/* I'm a workqueue worker */
#define PF_FORKNOEXEC		0x00000040	/* forked but didn't exec */
#define PF_MCE_PROCESS  	0x00000080      /* process policy on mce errors */
#define PF_SUPERPRIV		0x00000100	/* used super-user privileges */
#define PF_DUMPCORE		0x00000200	/* dumped core */
#define PF_SIGNALED		0x00000400	/* killed by a signal */
#define PF_MEMALLOC		0x00000800	/* Allocating memory */
#define PF_NPROC_EXCEEDED	0x00001000	/* set_user noticed that RLIMIT_NPROC was exceeded */
#define PF_USED_MATH		0x00002000	/* if unset the fpu must be initialized before use */
#define PF_USED_ASYNC		0x00004000	/* used async_schedule*(), used by module init */
#define PF_NOFREEZE		0x00008000	/* this thread should not be frozen */
#define PF_FROZEN		0x00010000	/* frozen for system suspend */
#define PF_FSTRANS		0x00020000	/* inside a filesystem transaction */
#define PF_KSWAPD		0x00040000	/* I am kswapd */
#define PF_MEMALLOC_NOIO	0x00080000	/* Allocating memory without IO involved */
#define PF_LESS_THROTTLE	0x00100000	/* Throttle me less: I clean memory */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define PF_RANDOMIZE		0x00400000	/* randomize virtual address space */
#define PF_SWAPWRITE		0x00800000	/* Allowed to write to swap */
#define PF_NO_SETAFFINITY	0x04000000	/* Userland is not allowed to meddle with cpus_allowed */

/* Task command name length */
#define TASK_COMM_LEN		16

/* Maximum timeout period */
#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX

struct sched_param {
	int sched_priority;
};

struct load_weight {
	unsigned long		weight;
	u32			inv_weight;
};

#ifdef CONFIG_SCHEDSTATS
struct sched_statistics {
	u64			wait_start;
	u64			wait_max;
	u64			wait_count;
	u64			wait_sum;
	u64			iowait_count;
	u64			iowait_sum;

	u64			sleep_start;
	u64			sleep_max;
	u64			sum_sleep_runtime;

	u64			block_start;
	u64			block_max;
	u64			exec_max;
	u64			slice_max;

	u64			nr_wakeups;
	u64			nr_wakeups_sync;
	u64			nr_wakeups_local;
	u64			nr_wakeups_remote;
	u64			nr_wakeups_idle;
};
#endif

/*
 * sched_entity contains data shared by all scheduling class.
 * If a particular class need additional data, it will introduce another
 * structure, e.g., sched_rt_entity and sched_dl_entity.
 */
struct sched_entity {
	struct load_weight	load;		/*  for load-balancing */
	struct rb_node		run_node;
	unsigned int		on_rq;

	u64			exec_start;
	u64			sum_exec_runtime;
	u64			vruntime;
	u64			prev_sum_exec_runtime;

#ifdef CONFIG_SCHEDSTATS
	struct sched_statistics statistics;
#endif
};

struct sched_rt_entity {
	struct list_head	run_list;
	unsigned long		timeout;
	unsigned long		watchdog_stamp;
	unsigned int		time_slice;

	struct sched_rt_entity	*back;
};

struct sched_dl_entity {
};

/*
 * System call restart block.
 */
struct restart_block {
	long (*fn)(struct restart_block *);
	union {
		/* For futex_wait and futex_wait_requeue_pi */
		struct {
			u32 __user *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 __user *uaddr2;
		} futex;
	};
};

long do_no_restart_syscall(struct restart_block *parm);

/*
 * Wake-queues are lists of tasks with a pending wakeup, whose
 * callers have already marked the task as woken internally,
 * and can thus carry on. A common use case is being able to
 * do the wakeups once the corresponding user lock as been
 * released.
 *
 * We hold reference to each task in the list across the wakeup,
 * thus guaranteeing that the memory is still valid by the time
 * the actual wakeups are performed in wake_up_q().
 *
 * One per task suffices, because there's never a need for a task to be
 * in two wake queues simultaneously; it is forbidden to abandon a task
 * in a wake queue (a call to wake_up_q() _must_ follow), so if a task is
 * already in a wake queue, the wakeup will happen soon and the second
 * waker can just skip it.
 *
 * The WAKE_Q macro declares and initializes the list head.
 * wake_up_q() does NOT reinitialize the list; it's expected to be
 * called near the end of a function, where the fact that the queue is
 * not used again will be easy to see by inspection.
 *
 * Note that this can cause spurious wakeups. schedule() callers
 * must ensure the call is done inside a loop, confirming that the
 * wakeup condition has in fact occurred.
 */
struct wake_q_node {
	struct wake_q_node *next;
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

#define WAKE_Q_TAIL ((struct wake_q_node *) 0x01)
#define WAKE_Q(name)					\
	struct wake_q_head name = { WAKE_Q_TAIL, &name.first }

void wake_q_add(struct wake_q_head *head, struct task_struct *task);
void wake_up_q(struct wake_q_head *head);

struct robust_list_head;

/*
 * NOTE:
 * The number of threads within a process is represented by:
 *	[task_struct->signal->nr_threads]
 */

struct task_struct {
	volatile long		state;		/* -1 unrunnable, 0 runnable, >0 stopped */
	void			*stack;		/* kernel mode stack */
	atomic_t		usage;
	unsigned int		flags;		/* per-process flags */
	unsigned int		ptrace;
	struct file_system fs;

#ifdef CONFIG_SMP
	int			on_cpu;
	int			wake_cpu;
	struct task_struct	*last_wakee;
	struct llist_node	wake_entry;
#endif

/* Scheduling */
	int			on_rq;
	int			prio, static_prio, normal_prio;
	unsigned int		rt_priority;
	const struct sched_class *sched_class;
	struct sched_entity	se;
	struct sched_rt_entity	rt;
	struct sched_dl_entity	dl;

	int			policy;
	int			nr_cpus_allowed;
	cpumask_t		cpus_allowed;

	/* list of all task_structs in the system */
	struct list_head	tasks;

	struct mm_struct *mm, *active_mm;

/* Scheduler bits, serialized by scheduler locks */
	unsigned		sched_reset_on_fork:1;
	unsigned		sched_contributes_to_load:1;
	unsigned		sched_migrated:1;
	unsigned		sched_remote_wakeup:1;
	unsigned		:0; /* force alignment to the next boundary */

/* Exit state */
	int			exit_state;
	int			exit_code;
	int			exit_signal;

	int pdeath_signal;	/*  The signal sent when the parent dies  */
	unsigned long jobctl;	/* JOBCTL_*, siglock protected */

	unsigned restore_sigmask:1;

	int			in_iowait;

	struct restart_block	restart_block;

	pid_t			pid;
	pid_t			tgid;

	/*
	 * pointers to (original) parent process, youngest child,
	 * younger sibling, older sibling, respectively.
	 * (p->father can be replaced with p->real_parent->pid)
	 */
	struct task_struct __rcu *real_parent;	/* real parent process */
	struct task_struct __rcu *parent;	/* recipient of SIGCHLD, wait4() reports */
	/*
	 * children/sibling forms the list of my natural children
	 */
	struct list_head children;		/* list of my children */
	struct list_head sibling;		/* linkage in my parent's children list */
	struct task_struct *group_leader;	/* threadgroup leader */

	/*
	 * ptraced is the list of tasks this task is using ptrace on.
	 * This includes both natural children and PTRACE_ATTACH targets.
	 * p->ptrace_entry is p's link on the p->parent->ptraced list.
	 */
	struct list_head ptraced;
	struct list_head ptrace_entry;

	struct list_head thread_group;
	struct list_head thread_node;

	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

	cputime_t utime, stime, utimescaled, stimescaled;
	cputime_t gtime;

	unsigned long nvcsw, nivcsw;		/* voluntary/involuntary context switch counts */
	u64 start_time;				/* monotonic time in nsec */
	u64 real_start_time;			/* boot based time in nsec */

/* process credentials */
	struct cred *real_cred;		/* objective and real subjective task
					 * credentials (COW) */
	struct cred *cred;		/* effective (overridable) subjective task
					 * credentials (COW) */

	char comm[TASK_COMM_LEN];  /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by setup_new_exec */

/* signal handlers */
	struct signal_struct *signal;	/* including shared pending signals */
	struct sighand_struct *sighand;
	struct sigpending pending;	/* Private pending signals */
	/* restored if set_restore_sigmask() was used */
	sigset_t saved_sigmask;
	sigset_t blocked;		/* Mask of blocked signals */
	sigset_t real_blocked;		/* Temporary mask of blocked signals
					   Used by the rt_sigtimedwait() syscall */

	unsigned long sas_ss_sp;	/* Address of alternative signal handler stack */
	size_t sas_ss_size;		/* Size of alternative signal handler stack */
	unsigned sas_ss_flags;

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;

/* Open file information */
	struct files_struct *files;

	/* Protection of the PI data structures: */
	spinlock_t pi_lock;

	struct wake_q_node wake_q;

	/*
	 * Protection of (de-)allocation: mm, files, fs, tty, keyrings,
	 * mems_allowed, mempolicy
	 */
	spinlock_t alloc_lock;

#ifdef CONFIG_FUTEX
	struct robust_list_head __user *robust_list;
#endif

	int pagefault_disabled;

#ifdef CONFIG_COMP_PROCESSOR
/* Processor Manager Specific Data */
	struct processor_manager pm_data;
#endif

	void *private_strace;

	/* CPU-specific state of this task */
	struct thread_struct thread;

/*
 * WARNING: on x86, 'thread_struct' contains a variable-sized
 * structure.  It *MUST* be at the end of 'task_struct'.
 *
 * Do not put anything below here!
 */
};

union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

extern unsigned long total_forks;
extern int nr_threads;
extern spinlock_t tasklist_lock;

#define task_thread_info(task)	((struct thread_info *)((task)->stack))
#define task_stack_page(task)	((void *)((task)->stack))

static inline int get_nr_threads(struct task_struct *tsk)
{
	return tsk->signal->nr_threads;
}

static inline bool thread_group_leader(struct task_struct *p)
{
	return p->exit_signal >= 0;
}

/*
 * Do to the insanities of de_thread it is possible for a process
 * to have the pid of the thread group leader without actually being
 * the thread group leader.  For iteration through the pids in proc
 * all we care about is that we have a task with the appropriate
 * pid, we don't actually care if we have the right task.
 */
static inline bool has_group_leader_pid(struct task_struct *p)
{
	return p->pid == p->signal->leader_pid;
}

static inline int thread_group_empty(struct task_struct *p)
{
	return list_empty(&p->thread_group);
}

static inline
bool same_thread_group(struct task_struct *p1, struct task_struct *p2)
{
	return p1->signal == p2->signal;
}

static inline struct task_struct *next_thread(const struct task_struct *p)
{
	/* list_entry_rcu */
	return list_entry(p->thread_group.next, struct task_struct, thread_group);
}

extern union thread_union init_thread_union;
extern struct task_struct init_task;

#define tasklist_empty() \
	list_empty(&init_task.tasks)

#define next_task(p) \
	list_entry((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

#define __for_each_thread(signal, t)	\
	list_for_each_entry(t, &(signal)->thread_head, thread_node)

#define for_each_thread(p, t)		\
	__for_each_thread((p)->signal, t)

/* Careful: this is a double loop, 'break' won't work as expected. */
#define for_each_process_thread(p, t)	\
	for_each_process(p) for_each_thread(p, t)

/*
 * Careful: do_each_thread/while_each_thread is a double loop so
 *          'break' will not work as expected - use goto instead.
 */
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do

#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

/*
 * flag set/clear/test wrappers
 * - pass TIF_xxxx constants to these functions
 */

static inline void set_ti_thread_flag(struct thread_info *ti, int flag)
{
	set_bit(flag, (unsigned long *)&ti->flags);
}

static inline void clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_and_set_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_and_set_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_and_clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_and_clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_bit(flag, (unsigned long *)&ti->flags);
}

#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)

#define tif_need_resched()	test_thread_flag(TIF_NEED_RESCHED)
#define tif_need_checkpoint()	test_thread_flag(TIF_NEED_CHECKPOINT)

static __always_inline bool need_resched(void)
{
	return unlikely(tif_need_resched());
}

static __always_inline bool need_checkpoint(void)
{
	return unlikely(tif_need_checkpoint());
}

/*
 * set thread flags in other task's structures.
 * see asm/thread_info.h for tif_xxxx flags available:
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk, TIF_NEED_RESCHED);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk, TIF_NEED_RESCHED);
}

static inline int test_tsk_need_resched(struct task_struct *tsk)
{
	return unlikely(test_tsk_thread_flag(tsk, TIF_NEED_RESCHED));
}

static inline void set_tsk_need_checkpoint(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk, TIF_NEED_CHECKPOINT);
}

static inline void clear_tsk_need_checkpoint(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk, TIF_NEED_CHECKPOINT);
}

static inline int test_tsk_need_checkpoint(struct task_struct *tsk)
{
	return unlikely(test_tsk_thread_flag(tsk, TIF_NEED_CHECKPOINT));
}

/*
 * Return the address of the last usable long on the stack.
 *
 * When the stack grows down, this is just above the thread
 * info struct. Going any lower will corrupt the thread_info.
 */
static inline unsigned long *end_of_stack(struct task_struct *p)
{
	return (unsigned long *)(task_thread_info(p) + 1);
}

static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection: */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}

void show_call_trace(struct task_struct *task, struct pt_regs *regs, unsigned long *);
void show_stack_content(struct task_struct *task, struct pt_regs *regs, unsigned long *sp);
void show_general_task_info(struct task_struct *task);
void show_regs(struct pt_regs *regs);

/* Dump pt_regs purely */
void __show_regs(struct pt_regs *regs, int all);

/**
 * dump_stack	-	Dump the current stack
 *
 * By default, this function will just dump the *current* process's stack
 * and registers. If we have further requirement, e.g. dump *another* process's
 * stack, then we need to look back and improve this guy.
 */
static inline void dump_stack(void)
{
	show_general_task_info(current);
	show_stack_content(current, NULL, NULL);
	show_call_trace(current, NULL, NULL);
}

void setup_init_idleclass(struct task_struct *idle);
void setup_task_stack_end_magic(struct task_struct *tsk);

asmlinkage void schedule_tail(struct task_struct *prev);
int setup_sched_fork(unsigned long clone_flags, struct task_struct *p);
void sched_remove_from_rq(struct task_struct *p);

/* arch-hook to copy thread info while doing fork */
int copy_thread_tls(unsigned long, unsigned long, unsigned long,
		struct task_struct *, unsigned long);

/* Scheduler clock - returns current time in nanosec units */
unsigned long long sched_clock(void);

struct task_struct *copy_process(unsigned long clone_flags,
				 unsigned long stack_start,
				 unsigned long stack_size,
				 int __user *child_tidptr,
				 unsigned long tls, int node);

pid_t do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr,
	      unsigned long tls);

pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

void __init sched_init(void);
void __init sched_init_idle(struct task_struct *idle, int cpu);

long schedule_timeout(long timeout);
asmlinkage void schedule(void);
void schedule_preempt_disabled(void);

/* Called periodically in every tick */
void scheduler_tick(void);

/* Reschedule IPI */
#ifdef CONFIG_SMP
void sched_ttwu_pending(void);
void scheduler_ipi(void);
unsigned long wait_task_inactive(struct task_struct *, long match_state);
void do_set_cpus_allowed(struct task_struct *p,
			 const struct cpumask *new_mask);

int set_cpus_allowed_ptr(struct task_struct *p,
			 const struct cpumask *new_mask);
#else
static inline void sched_ttwu_pending(void) { }
static inline void scheduler_ipi(void) { }
static inline unsigned long wait_task_inactive(struct task_struct *p,
					       long match_state)
{
	return 1;
}
static inline void do_set_cpus_allowed(struct task_struct *p,
				       const struct cpumask *new_mask)
{
}
static inline int set_cpus_allowed_ptr(struct task_struct *p,
				       const struct cpumask *new_mask)
{
	if (!cpumask_test_cpu(0, new_mask))
		return -EINVAL;
	return 0;
}
#endif

int set_cpus_allowed_ptr(struct task_struct *p, const struct cpumask *new_mask);
long sched_setaffinity(pid_t pid, const struct cpumask *new_mask);

int wake_up_state(struct task_struct *p, unsigned int state);
int wake_up_process(struct task_struct *p);
void wake_up_new_task(struct task_struct *p);

/* kernel/exit.c */
void __wake_up_parent(struct task_struct *p, struct task_struct *parent);
void do_exit(long code);
void do_group_exit(int);
int is_current_pgrp_orphaned(void);

void __noreturn do_task_dead(void);
void cpu_idle(void);
int task_curr(const struct task_struct *p);

void __put_task_struct(struct task_struct *t);

static inline void put_task_struct(struct task_struct *t)
{
	if (atomic_dec_and_test(&t->usage))
		__put_task_struct(t);
}

static inline void get_task_struct(struct task_struct *t)
{
	atomic_inc(&t->usage);
}

/*
 * Protects ->fs, ->files, ->mm, ->group_info, ->comm, keyring
 * subscriptions and synchronises with wait4().  Also used in procfs.  Also
 * pins the final release of task.io_context.  Also protects ->cpuset and
 * ->cgroup.subsys[]. And ->vfork_done.
 *
 * Nests both inside and outside of read_lock(&tasklist_lock).
 * It must not be nested with write_lock_irq(&tasklist_lock),
 * neither inside nor outside.
 */
static inline void task_lock(struct task_struct *p)
{
	spin_lock(&p->alloc_lock);
}

static inline void task_unlock(struct task_struct *p)
{
	spin_unlock(&p->alloc_lock);
}

void set_task_comm(struct task_struct *tsk, const char *buf);
char *get_task_comm(char *buf, struct task_struct *tsk);

#ifdef CONFIG_SMP
void kick_process(struct task_struct *tsk);
#else
static inline void kick_process(struct task_struct *tsk) { }
#endif

/*
 * Wrappers for p->thread_info->cpu access. No-op on UP.
 */
#ifdef CONFIG_SMP
static inline unsigned int task_cpu(const struct task_struct *p)
{
	return task_thread_info(p)->cpu;
}
void set_task_cpu(struct task_struct *p, unsigned int new_cpu);
#else
static inline unsigned int task_cpu(const struct task_struct *p) { return 0; }
static inline void set_task_cpu(struct task_struct *p, unsigned int new_cpu){ }
#endif

/* Attach to any functions which should be ignored in wchan output. */
#define __sched		__attribute__((__section__(".sched.text")))

/* Linker adds these: start and end of __sched functions */
extern char __sched_text_start[], __sched_text_end[];

/* Is this address in the __sched functions? */
int in_sched_functions(unsigned long addr);

static inline int signal_pending(struct task_struct *p)
{
	return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
}

static inline int __fatal_signal_pending(struct task_struct *p)
{
	return unlikely(sigismember(&p->pending.signal, SIGKILL));
}

static inline int fatal_signal_pending(struct task_struct *p)
{
	return signal_pending(p) && __fatal_signal_pending(p);
}

static inline int signal_pending_state(long state, struct task_struct *p)
{
	if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
		return 0;
	if (!signal_pending(p))
		return 0;

	return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
}

/* arch-specific exit */
void exit_thread(struct task_struct *tsk);

void exit_files(struct task_struct *tsk);

/* flush stale state in sys_exec() time */
void flush_thread(void);

#define SD_LOAD_BALANCE		0x0001	/* Do load balancing on this domain. */
#define SD_BALANCE_NEWIDLE	0x0002	/* Balance when about to become idle */
#define SD_BALANCE_EXEC		0x0004	/* Balance on exec */
#define SD_BALANCE_FORK		0x0008	/* Balance on fork, clone */
#define SD_BALANCE_WAKE		0x0010  /* Balance on wakeup */
#define SD_WAKE_AFFINE		0x0020	/* Wake task to waking CPU */
#define SD_ASYM_CPUCAPACITY	0x0040  /* Groups have different max cpu capacities */
#define SD_SHARE_CPUCAPACITY	0x0080	/* Domain members share cpu capacity */
#define SD_SHARE_POWERDOMAIN	0x0100	/* Domain members share power domain */
#define SD_SHARE_PKG_RESOURCES	0x0200	/* Domain members share cpu pkg resources */
#define SD_SERIALIZE		0x0400	/* Only a single load balancing instance */
#define SD_ASYM_PACKING		0x0800  /* Place busy groups earlier in the domain */
#define SD_PREFER_SIBLING	0x1000	/* Prefer to place tasks in a sibling domain */
#define SD_OVERLAP		0x2000	/* sched_domains of this level overlap */
#define SD_NUMA			0x4000	/* cross-node balancing */

/*
 * task->jobctl flags
 */
#define JOBCTL_STOP_SIGMASK	0xffff	/* signr of the last group stop */

#define JOBCTL_STOP_DEQUEUED_BIT 16	/* stop signal dequeued */
#define JOBCTL_STOP_PENDING_BIT	17	/* task should stop for group stop */
#define JOBCTL_STOP_CONSUME_BIT	18	/* consume group stop count */
#define JOBCTL_TRAP_STOP_BIT	19	/* trap for STOP */
#define JOBCTL_TRAP_NOTIFY_BIT	20	/* trap for NOTIFY */
#define JOBCTL_TRAPPING_BIT	21	/* switching to TRACED */
#define JOBCTL_LISTENING_BIT	22	/* ptracer is listening for events */

#define JOBCTL_STOP_DEQUEUED	(1UL << JOBCTL_STOP_DEQUEUED_BIT)
#define JOBCTL_STOP_PENDING	(1UL << JOBCTL_STOP_PENDING_BIT)
#define JOBCTL_STOP_CONSUME	(1UL << JOBCTL_STOP_CONSUME_BIT)
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
#define JOBCTL_TRAP_NOTIFY	(1UL << JOBCTL_TRAP_NOTIFY_BIT)
#define JOBCTL_TRAPPING		(1UL << JOBCTL_TRAPPING_BIT)
#define JOBCTL_LISTENING	(1UL << JOBCTL_LISTENING_BIT)

#define JOBCTL_TRAP_MASK	(JOBCTL_TRAP_STOP | JOBCTL_TRAP_NOTIFY)
#define JOBCTL_PENDING_MASK	(JOBCTL_STOP_PENDING | JOBCTL_TRAP_MASK)

bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask);
void task_clear_jobctl_trapping(struct task_struct *task);
void task_clear_jobctl_pending(struct task_struct *task, unsigned long mask);

void __init fork_init(void);
extern int arch_task_struct_size __read_mostly;
extern int arch_task_struct_order __read_mostly;

void exit_itimers(struct signal_struct *);
void flush_itimer_signals(void);

void set_current_blocked(sigset_t *);
void __set_current_blocked(const sigset_t *);

/* Higher-quality implementation, used if TIF_RESTORE_SIGMASK doesn't exist. */
static inline void set_restore_sigmask(void)
{
	current->restore_sigmask = true;
	WARN_ON(!test_thread_flag(TIF_SIGPENDING));
}
static inline void clear_restore_sigmask(void)
{
	current->restore_sigmask = false;
}
static inline bool test_restore_sigmask(void)
{
	return current->restore_sigmask;
}
static inline bool test_and_clear_restore_sigmask(void)
{
	if (!current->restore_sigmask)
		return false;
	current->restore_sigmask = false;
	return true;
}

static inline void restore_saved_sigmask(void)
{
	if (test_and_clear_restore_sigmask())
		__set_current_blocked(&current->saved_sigmask);
}

static inline sigset_t *sigmask_to_save(void)
{
	sigset_t *res = &current->blocked;
	if (unlikely(test_restore_sigmask()))
		res = &current->saved_sigmask;
	return res;
}

extern struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
							unsigned long *flags);

static inline struct sighand_struct *lock_task_sighand(struct task_struct *tsk,
						       unsigned long *flags)
{
	struct sighand_struct *ret;

	ret = __lock_task_sighand(tsk, flags);
	(void)__cond_lock(&tsk->sighand->siglock, ret);
	return ret;
}

static inline void unlock_task_sighand(struct task_struct *tsk,
						unsigned long *flags)
{
	spin_unlock_irqrestore(&tsk->sighand->siglock, *flags);
}

#define SS_ONSTACK	1
#define SS_DISABLE	2

/* bit-flags */
#define SS_AUTODISARM	(1U << 31)	/* disable sas during sighandling */
/* mask for all SS_xxx flags */
#define SS_FLAG_BITS	SS_AUTODISARM

#define MINSIGSTKSZ	2048
#define SIGSTKSZ	8192

/*
 * True if we are on the alternate signal stack.
 */
static inline int on_sig_stack(unsigned long sp)
{
	/*
	 * If the signal stack is SS_AUTODISARM then, by construction, we
	 * can't be on the signal stack unless user code deliberately set
	 * SS_AUTODISARM when we were already on it.
	 *
	 * This improves reliability: if user state gets corrupted such that
	 * the stack pointer points very close to the end of the signal stack,
	 * then this check will enable the signal to be handled anyway.
	 */
	if (current->sas_ss_flags & SS_AUTODISARM)
		return 0;

	return sp > current->sas_ss_sp &&
		sp - current->sas_ss_sp <= current->sas_ss_size;
}

static inline int sas_ss_flags(unsigned long sp)
{
	if (!current->sas_ss_size)
		return SS_DISABLE;

	return on_sig_stack(sp) ? SS_ONSTACK : 0;
}

static inline void sas_ss_reset(struct task_struct *p)
{
	p->sas_ss_sp = 0;
	p->sas_ss_size = 0;
	p->sas_ss_flags = SS_DISABLE;
}

static inline unsigned long sigsp(unsigned long sp, struct ksignal *ksig)
{
	if (unlikely((ksig->ka.sa.sa_flags & SA_ONSTACK)) && ! sas_ss_flags(sp))
		return current->sas_ss_sp + current->sas_ss_size;
	return sp;
}

#define save_altstack_ex(uss, sp) do { \
	stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	put_user_ex((void __user *)t->sas_ss_sp, &__uss->ss_sp); \
	put_user_ex(t->sas_ss_flags, &__uss->ss_flags); \
	put_user_ex(t->sas_ss_size, &__uss->ss_size); \
	if (t->sas_ss_flags & SS_AUTODISARM) \
		sas_ss_reset(t); \
} while (0);

int restore_altstack(const stack_t __user *uss);

/*
 * cond_resched() and cond_resched_lock(): latency reduction via
 * explicit rescheduling in places that are safe. The return
 * value indicates whether a reschedule was done in fact.
 * cond_resched_lock() will drop the spinlock before scheduling,
 * cond_resched_softirq() will enable bhs before scheduling.
 */
#ifndef CONFIG_PREEMPT
extern int _cond_resched(void);
#else
static inline int _cond_resched(void) { return 0; }
#endif

static inline void ___might_sleep(const char *file, int line,
				   int preempt_offset) { }

#define cond_resched() ({			\
	___might_sleep(__FILE__, __LINE__, 0);	\
	_cond_resched();			\
})

/* lib/dump_task_struct.c */
#define DUMP_TASK_STRUCT_SIGNAL	0x1
void dump_task_struct(struct task_struct *p, int dump_flags);

/*
 * Only dump TASK_* tasks. (0 for all tasks)
 */
void show_state_filter(unsigned long state_filter, bool print_rq);

static inline void show_sched_state(void)
{
	show_state_filter(0, true);
}

void release_task(struct task_struct * p);
bool do_notify_parent(struct task_struct *tsk, int sig);

#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))

/* TODO: One process one process group */
static inline pid_t task_pgrp(struct task_struct *task)
{
	return task->group_leader->pid;
}

static inline pid_t task_session(struct task_struct *task)
{
	return task->group_leader->pid;
}

enum sched_state {
	SCHED_DOWN,
	SCHED_UP,
};

extern int scheduler_state;

#endif /* _LEGO_SCHED_H_ */
