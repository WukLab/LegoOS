/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/utsname.h>
#include <generated/compile.h>
#include <generated/utsrelease.h>

struct utsname utsname = {
	.sysname	= UTS_SYSNAME,
	.nodename	= UTS_NODENAME,
	.release	= UTS_RELEASE,
	.version	= UTS_VERSION,
	.machine	= UTS_MACHINE,
	.domainname	= UTS_DOMAINNAME,
};

/* FIXED STRINGS! Don't touch! */
const char lego_banner[] =
	"LegoOS version " UTS_RELEASE " (" LEGO_COMPILE_BY "@"
	LEGO_COMPILE_HOST ") (" LEGO_COMPILER ") " UTS_VERSION "\n";

const char lego_proc_banner[] =
	"%s version %s"
	" (" LEGO_COMPILE_BY "@" LEGO_COMPILE_HOST ")"
	" (" LEGO_COMPILER ") %s\n";
