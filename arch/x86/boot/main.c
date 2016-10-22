/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Initialize ENV and fetch HW info from BIOS, then jump to PM
 */

#include <asm/boot.h>
#include <asm/setup.h>
#include <asm/bootparam.h>

#include "boot.h"
#include "string.h"

struct boot_params boot_params __attribute__((aligned(16)));

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 */
static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	BUILD_BUG_ON(sizeof(boot_params) != 4096);
	memcpy(&boot_params.hdr, &hdr, sizeof(hdr));

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

void main(void)
{
	/* Copy the boot header into the 'zeropage' */
	copy_boot_params();

	printf("%s\n", kernel_version);
	printf("cs = 0x%x ", cs());
	printf("es = 0x%x ", es());
	printf("ds = 0x%x ", ds());
	printf("fs = 0x%x ", fs());

	die();
}
