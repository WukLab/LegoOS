#ifndef LWIP_ARCH_THREAD_H
#define LWIP_ARCH_THREAD_H

#include <lego/types.h>

typedef u32 thread_id_t;

void thread_init(void);
thread_id_t thread_id(void);
void thread_wakeup(volatile u32 *addr);
void thread_wait(volatile u32 *addr, u32 val, u32 msec);
int thread_wakeups_pending(void);
int thread_onhalt(void (*fun)(thread_id_t));
int thread_create(thread_id_t *tid, const char *name, 
		void (*entry)(u64), u64 arg);
void thread_yield(void);
void thread_halt(void);

#endif
