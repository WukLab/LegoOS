#include <lego/types.h>
#include <lego/printk.h>
#include <lego/string.h>
#include <lego/bug.h>
#include <lego/err.h>
#include <asm/page_types.h>

#include <net/arch/thread.h>
#include <net/arch/threadq.h>
#include <net/arch/setjmp.h>
#include <net/arch/sys_arch.h>

static thread_id_t max_tid;
static struct thread_context *cur_tc;

static struct thread_queue thread_queue;
static struct thread_queue kill_queue;

void
thread_init(void) {
    threadq_init(&thread_queue);
    max_tid = 0;
}

u32
thread_id(void) {
    return cur_tc->tc_tid;
}

void
thread_wakeup(volatile u32 *addr) {
    struct thread_context *tc = thread_queue.tq_first;
    while (tc) {
	if (tc->tc_wait_addr == addr)
	    tc->tc_wakeup = 1;
	tc = tc->tc_queue_link;
    }
}

void
thread_wait(volatile u32 *addr, u32 val, u32 msec) {
#if 0
    u32 s = sys_time_msec();
    u32 p = s;

    cur_tc->tc_wait_addr = addr;
    cur_tc->tc_wakeup = 0;

    while (p < msec) {
	if (p < s)
	    break;
	if (addr && *addr != val)
	    break;
	if (cur_tc->tc_wakeup)
	    break;

	thread_yield();
	p = sys_time_msec();
    }

    cur_tc->tc_wait_addr = 0;
    cur_tc->tc_wakeup = 0;
#endif
}

int
thread_wakeups_pending(void)
{
    struct thread_context *tc = thread_queue.tq_first;
    int n = 0;
    while (tc) {
	if (tc->tc_wakeup)
	    ++n;
	tc = tc->tc_queue_link;
    }
    return n;
}

int
thread_onhalt(void (*fun)(thread_id_t)) {
    if (cur_tc->tc_nonhalt >= THREAD_NUM_ONHALT)
	return -ENOMEM;

    cur_tc->tc_onhalt[cur_tc->tc_nonhalt++] = fun;
    return 0;
}

static thread_id_t
alloc_tid(void) {
    int tid = max_tid++;
    if (max_tid == (u32)~0)
	panic("alloc_tid: no more thread ids");
    return tid;
}

static void
thread_set_name(struct thread_context *tc, const char *name)
{
    strncpy(tc->tc_name, name, name_size - 1);
    tc->tc_name[name_size - 1] = 0;
}

static void
thread_entry(void) {
    cur_tc->tc_entry(cur_tc->tc_arg);
    thread_halt();
}

int
thread_create(thread_id_t *tid, const char *name, 
		void (*entry)(u64), u64 arg) {
    struct thread_context *tc = kmalloc(sizeof(struct thread_context), GFP_KERNEL);
    if (!tc)
	return -ENOMEM;

    memset(tc, 0, sizeof(struct thread_context));
    
    thread_set_name(tc, name);
    tc->tc_tid = alloc_tid();

    tc->tc_stack_bottom = kmalloc(stack_size, GFP_KERNEL);
    if (!tc->tc_stack_bottom) {
	kfree(tc);
	return -ENOMEM;
    }

    void *stacktop = tc->tc_stack_bottom + stack_size;
    // Terminate stack unwinding
    stacktop = stacktop - 8;
    memset(stacktop, 0, 8);
    
    memset(&tc->tc_jb, 0, sizeof(tc->tc_jb));
    tc->tc_jb.jb_rsp = (u64)stacktop;
    tc->tc_jb.jb_rip = (u64)&thread_entry;
    tc->tc_entry = entry;
    tc->tc_arg = arg;

    threadq_push(&thread_queue, tc);

    if (tid)
	*tid = tc->tc_tid;
    return 0;
}

static void
thread_clean(struct thread_context *tc) {
    if (!tc) return;

    int i;
    for (i = 0; i < tc->tc_nonhalt; i++)
	tc->tc_onhalt[i](tc->tc_tid);
    kfree(tc->tc_stack_bottom);
    kfree(tc);
}

void
thread_halt() {
    // right now the kill_queue will never be more than one
    // clean up a thread if one is on the queue
    thread_clean(threadq_pop(&kill_queue));

    threadq_push(&kill_queue, cur_tc);
    cur_tc = NULL;
    thread_yield();
    // WHAT IF THERE ARE NO MORE THREADS? HOW DO WE STOP?
    // when yield has no thread to run, it will return here!
#if 0
    exit(1);
#endif
}

void
thread_yield(void) {
#if 0
    struct thread_context *next_tc = threadq_pop(&thread_queue);

    if (!next_tc)
	return;

    if (cur_tc) {
	if (lego_setjmp(&cur_tc->tc_jb) != 0)
	    return;
	threadq_push(&thread_queue, cur_tc);
    }

    cur_tc = next_tc;
    lego_longjmp(&cur_tc->tc_jb, 1);
    #endif
}

static void
print_jb(struct thread_context *tc) {
    pr_debug("jump buffer for thread %s:\n", tc->tc_name);
    pr_debug("\trip: %lx\n", tc->tc_jb.jb_rip);
    pr_debug("\trsp: %lx\n", tc->tc_jb.jb_rsp);
    pr_debug("\trbp: %lx\n", tc->tc_jb.jb_rbp);
    pr_debug("\trbx: %lx\n", tc->tc_jb.jb_rbx);
    pr_debug("\trsi: %lx\n", tc->tc_jb.jb_rsi);
    pr_debug("\trdi: %lx\n", tc->tc_jb.jb_rdi);
    pr_debug("\tr15: %lx\n", tc->tc_jb.jb_r15);
    pr_debug("\tr14: %lx\n", tc->tc_jb.jb_r14);
    pr_debug("\tr13: %lx\n", tc->tc_jb.jb_r13);
    pr_debug("\tr12: %lx\n", tc->tc_jb.jb_r12);
    pr_debug("\tr11: %lx\n", tc->tc_jb.jb_r11);
    pr_debug("\tr10: %lx\n", tc->tc_jb.jb_r10);
    pr_debug("\tr9: %lx\n", tc->tc_jb.jb_r9);
    pr_debug("\tr8: %lx\n", tc->tc_jb.jb_r8);
}
