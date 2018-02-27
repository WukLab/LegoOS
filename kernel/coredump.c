/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * TODO: coredump
 * Useful for debugging
 */

#include <lego/init.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/signal.h>
#include <lego/signalfd.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>

void do_coredump(const siginfo_t *siginfo)
{
}
