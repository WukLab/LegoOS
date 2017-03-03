/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * :-)
 * piggyback the realmode trampoline code
 */

	.section ".init.trampoline","ax"
.globl trampoline_start, trampoline_end
trampoline_start:
.incbin "arch/x86/realmode/rm/trampoline.bin"
trampoline_end:
