#include <asm/io.h>
#include <asm/asm.h>
#include <asm/page.h>
#include <asm/numa.h>
#include <asm/setup.h>

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/tty.h>
#include <lego/irq.h>
#include <lego/init.h>
#include <lego/list.h>
#include <lego/slab.h>
#include <lego/time.h>
#include <lego/string.h>
#include <lego/atomic.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/spinlock.h>

/* Screen information used by kernel */
struct screen_info screen_info;

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);

/* Builtin command line from kconfig */
#ifdef CONFIG_CMDLINE_BOOL
static char __initdata builtin_cmdline[COMMAND_LINE_SIZE] = CONFIG_CMDLINE;
#endif

/* Untouched command line saved by head, passed from boot loader */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/* Concatenated command line from boot and builtin */
static char command_line[COMMAND_LINE_SIZE];

static void internal_test(void);

asmlinkage void __init start_kernel(void)
{
	local_irq_disable();

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

	/* Architecture-Specific Initialization */
	setup_arch();

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
	 * Make IRQ subsystem functional
	 * and then enable interrupt.
	 */
	irq_init();
	local_irq_enable();

	timekeeping_init();
	time_init();

	internal_test();
	hlt();
}

static void internal_test(void)
{
	asm ("int $0x30");
	asm ("int $0x3f");
	asm ("int $0xef");
	asm ("int $0xef");
}
