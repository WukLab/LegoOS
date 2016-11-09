/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <generated/compile.h>
#include <generated/utsrelease.h>

/* FIXED STRINGS! Don't touch! */
const char disos_banner[] =
	"DisOS version " UTS_RELEASE " (" DISOS_COMPILE_BY "@"
	DISOS_COMPILE_HOST ") (" DISOS_COMPILER ") " UTS_VERSION "\n";

const char disos_proc_banner[] =
	"%s version %s"
	" (" DISOS_COMPILE_BY "@" DISOS_COMPILE_HOST ")"
	" (" DISOS_COMPILER ") %s\n";
