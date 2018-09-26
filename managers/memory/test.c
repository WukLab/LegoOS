/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/delay.h>
#include <lego/kernel.h>
#include <lego/printk.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/profile.h>
#include <lego/memblock.h>
#include <lego/fit_ibapi.h>
#include <lego/completion.h>
#include <lego/comp_storage.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/stat.h>
#include <memory/loader.h>
#include <memory/distvm.h>
#include <memory/replica.h>
#include <memory/thread_pool.h>
#include <memory/pgcache.h>

void handle_p2m_test(struct p2m_test_msg *msg, struct thpool_buffer *tb)
{
	tb_set_tx_size(tb, msg->reply_len);
}

void handle_p2m_test_noreply(struct p2m_test_msg *msg, struct thpool_buffer *tb)
{
	tb_set_tx_size(tb, msg->reply_len);
}
