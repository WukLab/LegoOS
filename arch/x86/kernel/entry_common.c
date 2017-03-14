#include <lego/sched.h>
#include <lego/kernel.h>
#include <asm/ptrace.h>

/* Called with IRQs disabled. */
__visible inline void prepare_exit_to_usermode(struct pt_regs *regs)
{
	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();

	/* TODO: not impl */
	BUG();
}
