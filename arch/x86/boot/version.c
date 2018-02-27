/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 */

#include "boot.h"
#include <generated/utsrelease.h>
#include <generated/compile.h>

const char kernel_version[] = 
	UTS_RELEASE " (" LEGO_COMPILE_BY "@" LEGO_COMPILE_HOST ") "
	UTS_VERSION;
