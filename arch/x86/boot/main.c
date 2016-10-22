/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Initialize ENV and fetch HW info from BIOS, then jump to PM
 */

#include <asm/boot.h>
#include <asm/bootparam.h>

#include "boot.h"
#include "string.h"

void main(void)
{
	printf("%s\n", kernel_version);
}
