/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved.
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

#include <rdma/ib_mad.h>

#include <lego/mlx4/cmd.h>
#include <lego/rbtree.h>
#include <lego/idr.h>
#include <rdma/ib_cm.h>

#include "mlx4_ib.h"

#define CM_CLEANUP_CACHE_TIMEOUT  (5 * HZ)

struct id_map_entry {
	struct rb_node node;

	u32 sl_cm_id;
	u32 pv_cm_id;
	int slave_id;
	int scheduled_delete;
	struct mlx4_ib_dev *dev;

	struct list_head list;
	struct delayed_work timeout;
};

struct cm_generic_msg {
	struct ib_mad_hdr hdr;

	__be32 local_comm_id;
	__be32 remote_comm_id;
};

struct cm_req_msg {
	unsigned char unused[0x60];
	union ib_gid primary_path_sgid;
};


static void set_local_comm_id(struct ib_mad *mad, u32 cm_id)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;
	msg->local_comm_id = cpu_to_be32(cm_id);
}

static u32 get_local_comm_id(struct ib_mad *mad)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;

	return be32_to_cpu(msg->local_comm_id);
}

static void set_remote_comm_id(struct ib_mad *mad, u32 cm_id)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;
	msg->remote_comm_id = cpu_to_be32(cm_id);
}

static u32 get_remote_comm_id(struct ib_mad *mad)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;

	return be32_to_cpu(msg->remote_comm_id);
}

static union ib_gid gid_from_req_msg(struct ib_device *ibdev, struct ib_mad *mad)
{
	struct cm_req_msg *msg = (struct cm_req_msg *)mad;

	return msg->primary_path_sgid;
}

/* Lock should be taken before called */
static struct id_map_entry *
id_map_find_by_sl_id(struct ib_device *ibdev, u32 slave_id, u32 sl_cm_id)
{
	struct rb_root *sl_id_map = &to_mdev(ibdev)->sriov.sl_id_map;
	struct rb_node *node = sl_id_map->rb_node;

	while (node) {
		struct id_map_entry *id_map_entry =
			rb_entry(node, struct id_map_entry, node);

		if (id_map_entry->sl_cm_id > sl_cm_id)
			node = node->rb_left;
		else if (id_map_entry->sl_cm_id < sl_cm_id)
			node = node->rb_right;
		else if (id_map_entry->slave_id > slave_id)
			node = node->rb_left;
		else if (id_map_entry->slave_id < slave_id)
			node = node->rb_right;
		else
			return id_map_entry;
	}
	return NULL;
}

static void id_map_ent_timeout(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct id_map_entry *ent = container_of(delay, struct id_map_entry, timeout);
	struct id_map_entry *db_ent, *found_ent;
	struct mlx4_ib_dev *dev = ent->dev;
	struct mlx4_ib_sriov *sriov = &dev->sriov;
	struct rb_root *sl_id_map = &sriov->sl_id_map;
	int pv_id = (int) ent->pv_cm_id;

	spin_lock(&sriov->id_map_lock);
	db_ent = (struct id_map_entry *)idr_find(&sriov->pv_id_table, pv_id);
	if (!db_ent)
		goto out;
	found_ent = id_map_find_by_sl_id(&dev->ib_dev, ent->slave_id, ent->sl_cm_id);
	if (found_ent && found_ent == ent)
		rb_erase(&found_ent->node, sl_id_map);
	idr_remove(&sriov->pv_id_table, pv_id);

out:
	list_del(&ent->list);
	spin_unlock(&sriov->id_map_lock);
	kfree(ent);
}

static void id_map_find_del(struct ib_device *ibdev, int pv_cm_id)
{
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;
	struct rb_root *sl_id_map = &sriov->sl_id_map;
	struct id_map_entry *ent, *found_ent;

	spin_lock(&sriov->id_map_lock);
	ent = (struct id_map_entry *)idr_find(&sriov->pv_id_table, pv_cm_id);
	if (!ent)
		goto out;
	found_ent = id_map_find_by_sl_id(ibdev, ent->slave_id, ent->sl_cm_id);
	if (found_ent && found_ent == ent)
		rb_erase(&found_ent->node, sl_id_map);
	idr_remove(&sriov->pv_id_table, pv_cm_id);
out:
	spin_unlock(&sriov->id_map_lock);
}

static void sl_id_map_add(struct ib_device *ibdev, struct id_map_entry *new)
{
	struct rb_root *sl_id_map = &to_mdev(ibdev)->sriov.sl_id_map;
	struct rb_node **link = &sl_id_map->rb_node, *parent = NULL;
	struct id_map_entry *ent;
	int slave_id = new->slave_id;
	int sl_cm_id = new->sl_cm_id;

	ent = id_map_find_by_sl_id(ibdev, slave_id, sl_cm_id);
	if (ent) {
		pr_debug("overriding existing sl_id_map entry (cm_id = %x)\n",
			 sl_cm_id);

		rb_replace_node(&ent->node, &new->node, sl_id_map);
		return;
	}

	/* Go to the bottom of the tree */
	while (*link) {
		parent = *link;
		ent = rb_entry(parent, struct id_map_entry, node);

		if (ent->sl_cm_id > sl_cm_id || (ent->sl_cm_id == sl_cm_id && ent->slave_id > slave_id))
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, sl_id_map);
}

static struct id_map_entry *
id_map_alloc(struct ib_device *ibdev, int slave_id, u32 sl_cm_id)
{
	int ret;
	struct id_map_entry *ent;
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;

	ent = kmalloc(sizeof (struct id_map_entry), GFP_KERNEL);
	if (!ent) {
		mlx4_ib_warn(ibdev, "Couldn't allocate id cache entry - out of memory\n");
		return ERR_PTR(-ENOMEM);
	}

	ent->sl_cm_id = sl_cm_id;
	ent->slave_id = slave_id;
	ent->scheduled_delete = 0;
	ent->dev = to_mdev(ibdev);
	INIT_DELAYED_WORK(&ent->timeout, id_map_ent_timeout);

	idr_preload(GFP_KERNEL);
	spin_lock(&to_mdev(ibdev)->sriov.id_map_lock);

	ret = idr_alloc_cyclic(&sriov->pv_id_table, ent, 0, 0, GFP_NOWAIT);
	if (ret >= 0) {
		ent->pv_cm_id = (u32)ret;
		sl_id_map_add(ibdev, ent);
		list_add_tail(&ent->list, &sriov->cm_list);
	}

	spin_unlock(&sriov->id_map_lock);
	idr_preload_end();

	if (ret >= 0)
		return ent;

	/*error flow*/
	kfree(ent);
	mlx4_ib_warn(ibdev, "No more space in the idr (err:0x%x)\n", ret);
	return ERR_PTR(-ENOMEM);
}

static struct id_map_entry *
id_map_get(struct ib_device *ibdev, int *pv_cm_id, int sl_cm_id, int slave_id)
{
	struct id_map_entry *ent;
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;

	spin_lock(&sriov->id_map_lock);
	if (*pv_cm_id == -1) {
		ent = id_map_find_by_sl_id(ibdev, sl_cm_id, slave_id);
		if (ent)
			*pv_cm_id = (int) ent->pv_cm_id;
	} else
		ent = (struct id_map_entry *)idr_find(&sriov->pv_id_table, *pv_cm_id);
	spin_unlock(&sriov->id_map_lock);

	return ent;
}

static void schedule_delayed(struct ib_device *ibdev, struct id_map_entry *id)
{
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;
	unsigned long flags;

	spin_lock(&sriov->id_map_lock);
	spin_lock_irqsave(&sriov->going_down_lock, flags);
	/*make sure that there is no schedule inside the scheduled work.*/
	if (!sriov->is_going_down) {
		id->scheduled_delete = 1;
		schedule_delayed_work(&id->timeout, CM_CLEANUP_CACHE_TIMEOUT);
	}
	spin_unlock_irqrestore(&sriov->going_down_lock, flags);
	spin_unlock(&sriov->id_map_lock);
}


