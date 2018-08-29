/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <lego/init.h>
#include <lego/err.h>
#include <lego/random.h>
#include <lego/spinlock.h>
#include <lego/slab.h>
#include <lego/dma-mapping.h>
#include <lego/kref.h>
#include <lego/workqueue.h>

#include <rdma/ib_pack.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_sa.h>
//#include "sa.h"

struct ib_sa_sm_ah {
	struct ib_ah        *ah;
	struct kref          ref;
	u16		     pkey_index;
	u8		     src_path_mask;
};

struct ib_sa_port {
	struct ib_mad_agent *agent;
	struct ib_sa_sm_ah  *sm_ah;
	struct work_struct   update_task;
	spinlock_t           ah_lock;
	u8                   port_num;
};

struct ib_sa_device {
	int                     start_port, end_port;
	struct ib_event_handler event_handler;
	struct ib_sa_port port[0];
};

struct ib_sa_query {
	void (*callback)(struct ib_sa_query *, int, struct ib_sa_mad *);
	void (*release)(struct ib_sa_query *);
	struct ib_sa_client    *client;
	struct ib_sa_port      *port;
	struct ib_mad_send_buf *mad_buf;
	struct ib_sa_sm_ah     *sm_ah;
	int			id;
};

struct ib_sa_service_query {
	void (*callback)(int, struct ib_sa_service_rec *, void *);
	void *context;
	struct ib_sa_query sa_query;
};

struct ib_sa_path_query {
	void (*callback)(int, struct ib_sa_path_rec *, void *);
	void *context;
	struct ib_sa_query sa_query;
};

struct ib_sa_guidinfo_query {
	void (*callback)(int, struct ib_sa_guidinfo_rec *, void *);
	void *context;
	struct ib_sa_query sa_query;
};

struct ib_sa_mcmember_query {
	void (*callback)(int, struct ib_sa_mcmember_rec *, void *);
	void *context;
	struct ib_sa_query sa_query;
};

static void ib_sa_add_one(struct ib_device *device);

static struct ib_client sa_client = {
	.name   = "sa",
	.add    = ib_sa_add_one,
};

static u32 tid;

static void update_sm_ah(struct work_struct *work)
{
}

static void send_handler(struct ib_mad_agent *agent,
			 struct ib_mad_send_wc *mad_send_wc)
{
	pr_info("%s(): TODO\n", __func__);
}

static void recv_handler(struct ib_mad_agent *mad_agent,
			 struct ib_mad_recv_wc *mad_recv_wc)
{
	struct ib_sa_query *query;
	struct ib_mad_send_buf *mad_buf;

	mad_buf = (void *) (unsigned long) mad_recv_wc->wc->wr_id;
	query = mad_buf->context[0];

	pr_info("%s(): TODO\n", __func__);
	ib_free_recv_mad(mad_recv_wc);
}

static void ib_sa_event(struct ib_event_handler *handler, struct ib_event *event)
{
	if (event->event == IB_EVENT_PORT_ERR    ||
	    event->event == IB_EVENT_PORT_ACTIVE ||
	    event->event == IB_EVENT_LID_CHANGE  ||
	    event->event == IB_EVENT_PKEY_CHANGE ||
	    event->event == IB_EVENT_SM_CHANGE   ||
	    event->event == IB_EVENT_CLIENT_REREGISTER) {
		/* update_sm_ah() */
		pr_info("%s(): TODO\n", __func__);
	}
}

/*
 * This function will register
 * 1) mad agent handlers
 * 2) ib event handlers
 */
static void ib_sa_add_one(struct ib_device *device)
{
	struct ib_sa_device *sa_dev;
	int s, e, i;

	if (rdma_node_get_transport(device->node_type) != RDMA_TRANSPORT_IB)
		return;

	if (device->node_type == RDMA_NODE_IB_SWITCH)
		s = e = 0;
	else {
		s = 1;
		e = device->phys_port_cnt;
	}

	sa_dev = kzalloc(sizeof *sa_dev +
			 (e - s + 1) * sizeof (struct ib_sa_port),
			 GFP_KERNEL);
	if (!sa_dev)
		return;

	sa_dev->start_port = s;
	sa_dev->end_port   = e;

	for (i = 0; i <= e - s; ++i) {
		spin_lock_init(&sa_dev->port[i].ah_lock);
		if (rdma_port_get_link_layer(device, i + 1) != IB_LINK_LAYER_INFINIBAND)
			continue;

		sa_dev->port[i].sm_ah    = NULL;
		sa_dev->port[i].port_num = i + s;

		sa_dev->port[i].agent =
			ib_register_mad_agent(device, i + s, IB_QPT_GSI,
					      NULL, 0, send_handler,
					      recv_handler, sa_dev);
		if (IS_ERR(sa_dev->port[i].agent))
			goto err;
	}

	ib_set_client_data(device, &sa_client, sa_dev);

	/*
	 * We register our event handler after everything is set up,
	 * and then update our cached info after the event handler is
	 * registered to avoid any problems if a port changes state
	 * during our initialization.
	 */

	INIT_IB_EVENT_HANDLER(&sa_dev->event_handler, device, ib_sa_event);
	if (ib_register_event_handler(&sa_dev->event_handler))
		goto err;

	for (i = 0; i <= e - s; ++i)
		if (rdma_port_get_link_layer(device, i + 1) == IB_LINK_LAYER_INFINIBAND)
			update_sm_ah(&sa_dev->port[i].update_task);

	return;

err:
	while (--i >= 0)
		if (rdma_port_get_link_layer(device, i + 1) == IB_LINK_LAYER_INFINIBAND)
			ib_unregister_mad_agent(sa_dev->port[i].agent);

	kfree(sa_dev);

	return;
}

int __init ib_sa_init(void)
{
	int ret;

	get_random_bytes(&tid, sizeof tid);

	ret = ib_register_client(&sa_client);
	if (ret) {
		printk(KERN_ERR "Couldn't register ib_sa client\n");
		goto err1;
	}

	return 0;

err1:
	return ret;
}
