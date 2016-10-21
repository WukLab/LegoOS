/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#include "boot.h"
#include <generated/utsrelease.h>
#include <generated/compile.h>

const char kernel_version[] = 
	UTS_RELEASE " (" DISOS_COMPILE_BY "@" DISOS_COMPILE_HOST ") "
	UTS_VERSION;
