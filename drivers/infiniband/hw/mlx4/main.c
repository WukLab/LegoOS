/*
 * Copyright (c) 2006, 2007 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
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
#include <lego/slab.h>
#include <lego/errno.h>

#include <rdma/ib_smi.h>
#include <uapi/rdma/ib_user_verbs.h>

#include <lego/mlx4/driver.h>
#include <lego/mlx4/cmd.h>

#include "mlx4_ib.h"
#include "user.h"

#define DRV_NAME	MLX4_IB_DRV_NAME
#define DRV_VERSION	"1.0"
#define DRV_RELDATE	"April 4, 2008"

static const char mlx4_ib_version[] =
	DRV_NAME ": Mellanox ConnectX InfiniBand driver v"
	DRV_VERSION " (" DRV_RELDATE ")\n";

#if 0
struct update_gid_work {
	struct work_struct	work;
	union ib_gid		gids[128];
	struct mlx4_ib_dev     *dev;
	int			port;
};

static struct workqueue_struct *wq;
#endif

static void init_query_mad(struct ib_smp *mad)
{
	mad->base_version  = 1;
	mad->mgmt_class    = IB_MGMT_CLASS_SUBN_LID_ROUTED;
	mad->class_version = 1;
	mad->method	   = IB_MGMT_METHOD_GET;
}

static int mlx4_ib_query_device(struct ib_device *ibdev,
				struct ib_device_attr *props)
{
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad = NULL;
	int err = -ENOMEM;

	in_mad  = kzalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
	if (!in_mad || !out_mad)
		goto out;

	init_query_mad(in_mad);
	in_mad->attr_id = IB_SMP_ATTR_NODE_INFO;

	err = mlx4_MAD_IFC(to_mdev(ibdev), MLX4_MAD_IFC_IGNORE_KEYS,
			   1, NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;

	memset(props, 0, sizeof *props);

	props->fw_ver = dev->dev->caps.fw_ver;
	props->device_cap_flags    = IB_DEVICE_CHANGE_PHY_PORT |
		IB_DEVICE_PORT_ACTIVE_EVENT		|
		IB_DEVICE_SYS_IMAGE_GUID		|
		IB_DEVICE_RC_RNR_NAK_GEN		|
		IB_DEVICE_BLOCK_MULTICAST_LOOPBACK;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_BAD_PKEY_CNTR)
		props->device_cap_flags |= IB_DEVICE_BAD_PKEY_CNTR;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_BAD_QKEY_CNTR)
		props->device_cap_flags |= IB_DEVICE_BAD_QKEY_CNTR;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_APM)
		props->device_cap_flags |= IB_DEVICE_AUTO_PATH_MIG;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_UD_AV_PORT)
		props->device_cap_flags |= IB_DEVICE_UD_AV_PORT_ENFORCE;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_IPOIB_CSUM)
		props->device_cap_flags |= IB_DEVICE_UD_IP_CSUM;
	if (dev->dev->caps.max_gso_sz && dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_BLH)
		props->device_cap_flags |= IB_DEVICE_UD_TSO;
	if (dev->dev->caps.bmme_flags & MLX4_BMME_FLAG_RESERVED_LKEY)
		props->device_cap_flags |= IB_DEVICE_LOCAL_DMA_LKEY;
	if ((dev->dev->caps.bmme_flags & MLX4_BMME_FLAG_LOCAL_INV) &&
	    (dev->dev->caps.bmme_flags & MLX4_BMME_FLAG_REMOTE_INV) &&
	    (dev->dev->caps.bmme_flags & MLX4_BMME_FLAG_FAST_REG_WR))
		props->device_cap_flags |= IB_DEVICE_MEM_MGT_EXTENSIONS;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC)
		props->device_cap_flags |= IB_DEVICE_XRC;
	if (dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_MEM_WINDOW)
		props->device_cap_flags |= IB_DEVICE_MEM_WINDOW;
	if (dev->dev->caps.bmme_flags & MLX4_BMME_FLAG_TYPE_2_WIN) {
		if (dev->dev->caps.bmme_flags & MLX4_BMME_FLAG_WIN_TYPE_2B)
			props->device_cap_flags |= IB_DEVICE_MEM_WINDOW_TYPE_2B;
		else
			props->device_cap_flags |= IB_DEVICE_MEM_WINDOW_TYPE_2A;
	}

	props->vendor_id	   = be32_to_cpup((__be32 *) (out_mad->data + 36)) &
		0xffffff;
	props->vendor_part_id	   = dev->dev->pdev->device;
	props->hw_ver		   = be32_to_cpup((__be32 *) (out_mad->data + 32));
	memcpy(&props->sys_image_guid, out_mad->data +	4, 8);

	props->max_mr_size	   = ~0ull;
	props->page_size_cap	   = dev->dev->caps.page_size_cap;
	props->max_qp		   = dev->dev->caps.num_qps - dev->dev->caps.reserved_qps;
	props->max_qp_wr	   = dev->dev->caps.max_wqes - MLX4_IB_SQ_MAX_SPARE;
	props->max_sge		   = min(dev->dev->caps.max_sq_sg,
					 dev->dev->caps.max_rq_sg);
	props->max_cq		   = dev->dev->caps.num_cqs - dev->dev->caps.reserved_cqs;
	props->max_cqe		   = dev->dev->caps.max_cqes;
	props->max_mr		   = dev->dev->caps.num_mpts - dev->dev->caps.reserved_mrws;
	props->max_pd		   = dev->dev->caps.num_pds - dev->dev->caps.reserved_pds;
	props->max_qp_rd_atom	   = dev->dev->caps.max_qp_dest_rdma;
	props->max_qp_init_rd_atom = dev->dev->caps.max_qp_init_rdma;
	props->max_res_rd_atom	   = props->max_qp_rd_atom * props->max_qp;
	props->max_srq		   = dev->dev->caps.num_srqs - dev->dev->caps.reserved_srqs;
	props->max_srq_wr	   = dev->dev->caps.max_srq_wqes - 1;
	props->max_srq_sge	   = dev->dev->caps.max_srq_sge;
	props->max_fast_reg_page_list_len = MLX4_MAX_FAST_REG_PAGES;
	props->local_ca_ack_delay  = dev->dev->caps.local_ca_ack_delay;
	props->atomic_cap	   = dev->dev->caps.flags & MLX4_DEV_CAP_FLAG_ATOMIC ?
		IB_ATOMIC_HCA : IB_ATOMIC_NONE;
	props->masked_atomic_cap   = props->atomic_cap;
	props->max_pkeys	   = dev->dev->caps.pkey_table_len[1];
	props->max_mcast_grp	   = dev->dev->caps.num_mgms + dev->dev->caps.num_amgms;
	props->max_mcast_qp_attach = dev->dev->caps.num_qp_per_mgm;
	props->max_total_mcast_qp_attach = props->max_mcast_qp_attach *
					   props->max_mcast_grp;
	props->max_map_per_fmr = dev->dev->caps.max_fmr_maps;

out:
	kfree(in_mad);
	kfree(out_mad);

	return err;
}

static enum rdma_link_layer
mlx4_ib_port_link_layer(struct ib_device *device, u8 port_num)
{
	struct mlx4_dev *dev = to_mdev(device)->dev;

	return dev->caps.port_mask[port_num] == MLX4_PORT_TYPE_IB ?
		IB_LINK_LAYER_INFINIBAND : IB_LINK_LAYER_ETHERNET;
}

static int ib_link_query_port(struct ib_device *ibdev, u8 port,
			      struct ib_port_attr *props, int netw_view)
{
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad = NULL;
	int ext_active_speed;
	int mad_ifc_flags = MLX4_MAD_IFC_IGNORE_KEYS;
	int err = -ENOMEM;

	in_mad  = kzalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
	if (!in_mad || !out_mad)
		goto out;

	init_query_mad(in_mad);
	in_mad->attr_id  = IB_SMP_ATTR_PORT_INFO;
	in_mad->attr_mod = cpu_to_be32(port);

	if (mlx4_is_mfunc(to_mdev(ibdev)->dev) && netw_view)
		mad_ifc_flags |= MLX4_MAD_IFC_NET_VIEW;

	err = mlx4_MAD_IFC(to_mdev(ibdev), mad_ifc_flags, port, NULL, NULL,
				in_mad, out_mad);
	if (err)
		goto out;


	props->lid		= be16_to_cpup((__be16 *) (out_mad->data + 16));
	props->lmc		= out_mad->data[34] & 0x7;
	props->sm_lid		= be16_to_cpup((__be16 *) (out_mad->data + 18));
	props->sm_sl		= out_mad->data[36] & 0xf;
	props->state		= out_mad->data[32] & 0xf;
	props->phys_state	= out_mad->data[33] >> 4;
	props->port_cap_flags	= be32_to_cpup((__be32 *) (out_mad->data + 20));
	if (netw_view)
		props->gid_tbl_len = out_mad->data[50];
	else
		props->gid_tbl_len = to_mdev(ibdev)->dev->caps.gid_table_len[port];
	props->max_msg_sz	= to_mdev(ibdev)->dev->caps.max_msg_sz;
	props->pkey_tbl_len	= to_mdev(ibdev)->dev->caps.pkey_table_len[port];
	props->bad_pkey_cntr	= be16_to_cpup((__be16 *) (out_mad->data + 46));
	props->qkey_viol_cntr	= be16_to_cpup((__be16 *) (out_mad->data + 48));
	props->active_width	= out_mad->data[31] & 0xf;
	props->active_speed	= out_mad->data[35] >> 4;
	props->max_mtu		= out_mad->data[41] & 0xf;
	props->active_mtu	= out_mad->data[36] >> 4;
	props->subnet_timeout	= out_mad->data[51] & 0x1f;
	props->max_vl_num	= out_mad->data[37] >> 4;
	props->init_type_reply	= out_mad->data[41] >> 4;

	/* Check if extended speeds (EDR/FDR/...) are supported */
	if (props->port_cap_flags & IB_PORT_EXTENDED_SPEEDS_SUP) {
		ext_active_speed = out_mad->data[62] >> 4;

		switch (ext_active_speed) {
		case 1:
			props->active_speed = IB_SPEED_FDR;
			break;
		case 2:
			props->active_speed = IB_SPEED_EDR;
			break;
		}
	}

	/* If reported active speed is QDR, check if is FDR-10 */
	if (props->active_speed == IB_SPEED_QDR) {
		init_query_mad(in_mad);
		in_mad->attr_id = MLX4_ATTR_EXTENDED_PORT_INFO;
		in_mad->attr_mod = cpu_to_be32(port);

		err = mlx4_MAD_IFC(to_mdev(ibdev), mad_ifc_flags, port,
				   NULL, NULL, in_mad, out_mad);
		if (err)
			goto out;

		/* Checking LinkSpeedActive for FDR-10 */
		if (out_mad->data[15] & 0x1)
			props->active_speed = IB_SPEED_FDR10;
	}

	/* Avoid wrong speed value returned by FW if the IB link is down. */
	if (props->state == IB_PORT_DOWN)
		 props->active_speed = IB_SPEED_SDR;

out:
	kfree(in_mad);
	kfree(out_mad);
	return err;
}

/* no RoCE support */
static int eth_link_query_port(struct ib_device *ibdev, u8 port,
			       struct ib_port_attr *props, int netw_view)
{
	WARN_ONCE(1, "No RoCE");
	return -EFAULT;
}

int __mlx4_ib_query_port(struct ib_device *ibdev, u8 port,
			 struct ib_port_attr *props, int netw_view)
{
	int err;

	memset(props, 0, sizeof *props);

	err = mlx4_ib_port_link_layer(ibdev, port) == IB_LINK_LAYER_INFINIBAND ?
		ib_link_query_port(ibdev, port, props, netw_view) :
				eth_link_query_port(ibdev, port, props, netw_view);

	return err;
}

static int mlx4_ib_query_port(struct ib_device *ibdev, u8 port,
			      struct ib_port_attr *props)
{
	/* returns host view */
	return __mlx4_ib_query_port(ibdev, port, props, 0);
}

int __mlx4_ib_query_gid(struct ib_device *ibdev, u8 port, int index,
			union ib_gid *gid, int netw_view)
{
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad = NULL;
	int err = -ENOMEM;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	int clear = 0;
	int mad_ifc_flags = MLX4_MAD_IFC_IGNORE_KEYS;

	in_mad  = kzalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
	if (!in_mad || !out_mad)
		goto out;

	init_query_mad(in_mad);
	in_mad->attr_id  = IB_SMP_ATTR_PORT_INFO;
	in_mad->attr_mod = cpu_to_be32(port);

	if (mlx4_is_mfunc(dev->dev) && netw_view)
		mad_ifc_flags |= MLX4_MAD_IFC_NET_VIEW;

	err = mlx4_MAD_IFC(dev, mad_ifc_flags, port, NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;

	memcpy(gid->raw, out_mad->data + 8, 8);

	if (mlx4_is_mfunc(dev->dev) && !netw_view) {
		if (index) {
			/* For any index > 0, return the null guid */
			err = 0;
			clear = 1;
			goto out;
		}
	}

	init_query_mad(in_mad);
	in_mad->attr_id  = IB_SMP_ATTR_GUID_INFO;
	in_mad->attr_mod = cpu_to_be32(index / 8);

	err = mlx4_MAD_IFC(dev, mad_ifc_flags, port,
			   NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;

	memcpy(gid->raw + 8, out_mad->data + (index % 8) * 8, 8);

out:
	if (clear)
		memset(gid->raw + 8, 0, 8);
	kfree(in_mad);
	kfree(out_mad);
	return err;
}

static int iboe_query_gid(struct ib_device *ibdev, u8 port, int index,
			  union ib_gid *gid)
{
	struct mlx4_ib_dev *dev = to_mdev(ibdev);

	*gid = dev->iboe.gid_table[port - 1][index];

	return 0;
}

static int mlx4_ib_query_gid(struct ib_device *ibdev, u8 port, int index,
			     union ib_gid *gid)
{
	if (rdma_port_get_link_layer(ibdev, port) == IB_LINK_LAYER_INFINIBAND)
		return __mlx4_ib_query_gid(ibdev, port, index, gid, 0);
	else
		return iboe_query_gid(ibdev, port, index, gid);
}

int __mlx4_ib_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			 u16 *pkey, int netw_view)
{
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad = NULL;
	int mad_ifc_flags = MLX4_MAD_IFC_IGNORE_KEYS;
	int err = -ENOMEM;

	in_mad  = kzalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
	if (!in_mad || !out_mad)
		goto out;

	init_query_mad(in_mad);
	in_mad->attr_id  = IB_SMP_ATTR_PKEY_TABLE;
	in_mad->attr_mod = cpu_to_be32(index / 32);

	if (mlx4_is_mfunc(to_mdev(ibdev)->dev) && netw_view)
		mad_ifc_flags |= MLX4_MAD_IFC_NET_VIEW;

	err = mlx4_MAD_IFC(to_mdev(ibdev), mad_ifc_flags, port, NULL, NULL,
			   in_mad, out_mad);
	if (err)
		goto out;

	*pkey = be16_to_cpu(((__be16 *) out_mad->data)[index % 32]);

out:
	kfree(in_mad);
	kfree(out_mad);
	return err;
}

static int mlx4_ib_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey)
{
	return __mlx4_ib_query_pkey(ibdev, port, index, pkey, 0);
}

static int mlx4_ib_modify_device(struct ib_device *ibdev, int mask,
				 struct ib_device_modify *props)
{
	struct mlx4_cmd_mailbox *mailbox;
	unsigned long flags;

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (!(mask & IB_DEVICE_MODIFY_NODE_DESC))
		return 0;

	if (mlx4_is_slave(to_mdev(ibdev)->dev))
		return -EOPNOTSUPP;

	spin_lock_irqsave(&to_mdev(ibdev)->sm_lock, flags);
	memcpy(ibdev->node_desc, props->node_desc, 64);
	spin_unlock_irqrestore(&to_mdev(ibdev)->sm_lock, flags);

	/*
	 * If possible, pass node desc to FW, so it can generate
	 * a 144 trap.  If cmd fails, just ignore.
	 */
	mailbox = mlx4_alloc_cmd_mailbox(to_mdev(ibdev)->dev);
	if (IS_ERR(mailbox))
		return 0;

	memset(mailbox->buf, 0, 256);
	memcpy(mailbox->buf, props->node_desc, 64);
	mlx4_cmd(to_mdev(ibdev)->dev, mailbox->dma, 1, 0,
		 MLX4_CMD_SET_NODE, MLX4_CMD_TIME_CLASS_A);

	mlx4_free_cmd_mailbox(to_mdev(ibdev)->dev, mailbox);

	return 0;
}

static int mlx4_SET_PORT(struct mlx4_ib_dev *dev, u8 port, int reset_qkey_viols,
			 u32 cap_mask)
{
	struct mlx4_cmd_mailbox *mailbox;
	int err;
	u8 is_eth = dev->dev->caps.port_type[port] == MLX4_PORT_TYPE_ETH;

	mailbox = mlx4_alloc_cmd_mailbox(dev->dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	memset(mailbox->buf, 0, 256);

	if (dev->dev->flags & MLX4_FLAG_OLD_PORT_CMDS) {
		*(u8 *) mailbox->buf	     = !!reset_qkey_viols << 6;
		((__be32 *) mailbox->buf)[2] = cpu_to_be32(cap_mask);
	} else {
		((u8 *) mailbox->buf)[3]     = !!reset_qkey_viols;
		((__be32 *) mailbox->buf)[1] = cpu_to_be32(cap_mask);
	}

	err = mlx4_cmd(dev->dev, mailbox->dma, port, is_eth, MLX4_CMD_SET_PORT,
		       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev->dev, mailbox);
	return err;
}

static int mlx4_ib_modify_port(struct ib_device *ibdev, u8 port, int mask,
			       struct ib_port_modify *props)
{
	struct ib_port_attr attr;
	u32 cap_mask;
	int err;

	mutex_lock(&to_mdev(ibdev)->cap_mask_mutex);

	err = mlx4_ib_query_port(ibdev, port, &attr);
	if (err)
		goto out;

	cap_mask = (attr.port_cap_flags | props->set_port_cap_mask) &
		~props->clr_port_cap_mask;

	err = mlx4_SET_PORT(to_mdev(ibdev), port,
			    !!(mask & IB_PORT_RESET_QKEY_CNTR),
			    cap_mask);

out:
	mutex_unlock(&to_mdev(ibdev)->cap_mask_mutex);
	return err;
}

static struct ib_pd *mlx4_ib_alloc_pd(struct ib_device *ibdev,
					void *context,
					void *udata)
{
	struct mlx4_ib_pd *pd;
	int err;

	pd = kmalloc(sizeof *pd, GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	err = mlx4_pd_alloc(to_mdev(ibdev)->dev, &pd->pdn);
	if (err) {
		kfree(pd);
		return ERR_PTR(err);
	}

	return &pd->ibpd;
}

static int mlx4_ib_dealloc_pd(struct ib_pd *pd)
{
	mlx4_pd_free(to_mdev(pd->device)->dev, to_mpd(pd)->pdn);
	kfree(pd);

	return 0;
}

int mlx4_ib_add_mc(struct mlx4_ib_dev *mdev, struct mlx4_ib_qp *mqp,
		   union ib_gid *gid)
{
	int ret = 0;

	if (!mqp->port)
		return 0;

	return ret;
}

static int init_node_data(struct mlx4_ib_dev *dev)
{
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad = NULL;
	int mad_ifc_flags = MLX4_MAD_IFC_IGNORE_KEYS;
	int err = -ENOMEM;

	in_mad  = kzalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
	if (!in_mad || !out_mad)
		goto out;

	init_query_mad(in_mad);
	in_mad->attr_id = IB_SMP_ATTR_NODE_DESC;
	if (mlx4_is_master(dev->dev))
		mad_ifc_flags |= MLX4_MAD_IFC_NET_VIEW;

	err = mlx4_MAD_IFC(dev, mad_ifc_flags, 1, NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;

	memcpy(dev->ib_dev.node_desc, out_mad->data, 64);

	in_mad->attr_id = IB_SMP_ATTR_NODE_INFO;

	err = mlx4_MAD_IFC(dev, mad_ifc_flags, 1, NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;

	dev->dev->rev_id = be32_to_cpup((__be32 *) (out_mad->data + 32));
	memcpy(&dev->ib_dev.node_guid, out_mad->data + 12, 8);

out:
	kfree(in_mad);
	kfree(out_mad);
	return err;
}

static void *mlx4_ib_add(struct mlx4_dev *dev)
{
	struct mlx4_ib_dev *ibdev;
	int num_ports = 0;
	int i;
	struct mlx4_ib_iboe *iboe;

	pr_info_once("%s", mlx4_ib_version);

	mlx4_foreach_non_ib_transport_port(i, dev)
		num_ports++;

	if (mlx4_is_mfunc(dev) && num_ports) {
		pr_err("%s RoCE is not supported over SRIOV as yet\n",
			dev_name(&dev->pdev->dev));
		return NULL;
	}

	num_ports = 0;
	mlx4_foreach_ib_transport_port(i, dev)
		num_ports++;

	/* No point in registering a device with no ports... */
	if (num_ports == 0)
		return NULL;

	ibdev = (struct mlx4_ib_dev *) ib_alloc_device(sizeof *ibdev);
	if (!ibdev) {
		printk(KERN_ERR "Device struct alloc failed\n");
		return NULL;
	}

	iboe = &ibdev->iboe;
	spin_lock_init(&iboe->lock);

	if (mlx4_pd_alloc(dev, &ibdev->priv_pdn))
		goto err_dealloc;

	if (mlx4_uar_alloc(dev, &ibdev->priv_uar))
		goto err_pd;

	ibdev->uar_map = ioremap((phys_addr_t) ibdev->priv_uar.pfn << PAGE_SHIFT,
				 PAGE_SIZE);
	if (!ibdev->uar_map)
		goto err_uar;
	MLX4_INIT_DOORBELL_LOCK(&ibdev->uar_lock);

	ibdev->dev = dev;

	strlcpy(ibdev->ib_dev.name, "mlx4_%d", IB_DEVICE_NAME_MAX);
	ibdev->ib_dev.node_type		= RDMA_NODE_IB_CA;
	ibdev->ib_dev.local_dma_lkey	= dev->caps.reserved_lkey;
	num_ports = 1;
	ibdev->num_ports		= num_ports;
	ibdev->ib_dev.phys_port_cnt     = ibdev->num_ports;
	ibdev->ib_dev.num_comp_vectors	= dev->caps.num_comp_vectors;
	ibdev->ib_dev.dma_device	= &dev->pdev->dev;

	if (dev->caps.userspace_caps)
		ibdev->ib_dev.uverbs_abi_ver = MLX4_IB_UVERBS_ABI_VERSION;
	else
		ibdev->ib_dev.uverbs_abi_ver = MLX4_IB_UVERBS_NO_DEV_CAPS_ABI_VERSION;

	ibdev->ib_dev.uverbs_cmd_mask	=
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_REG_MR)		|
		(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_RESIZE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_DETACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_XSRQ)		|
		(1ull << IB_USER_VERBS_CMD_OPEN_QP);

	ibdev->ib_dev.query_device	= mlx4_ib_query_device;
	ibdev->ib_dev.query_port	= mlx4_ib_query_port;
	ibdev->ib_dev.get_link_layer	= mlx4_ib_port_link_layer;
	ibdev->ib_dev.query_gid		= mlx4_ib_query_gid;
	ibdev->ib_dev.query_pkey	= mlx4_ib_query_pkey;
	ibdev->ib_dev.modify_device	= mlx4_ib_modify_device;
	ibdev->ib_dev.modify_port	= mlx4_ib_modify_port;
	ibdev->ib_dev.alloc_pd		= mlx4_ib_alloc_pd;
	ibdev->ib_dev.dealloc_pd	= mlx4_ib_dealloc_pd;
	ibdev->ib_dev.create_ah		= mlx4_ib_create_ah;
	ibdev->ib_dev.query_ah		= mlx4_ib_query_ah;
	ibdev->ib_dev.destroy_ah	= mlx4_ib_destroy_ah;
	ibdev->ib_dev.create_srq	= mlx4_ib_create_srq;
	ibdev->ib_dev.modify_srq	= mlx4_ib_modify_srq;
	ibdev->ib_dev.query_srq		= mlx4_ib_query_srq;
	ibdev->ib_dev.destroy_srq	= mlx4_ib_destroy_srq;
	ibdev->ib_dev.post_srq_recv	= mlx4_ib_post_srq_recv;
	ibdev->ib_dev.create_qp		= mlx4_ib_create_qp;
	ibdev->ib_dev.modify_qp		= mlx4_ib_modify_qp;
	ibdev->ib_dev.query_qp		= mlx4_ib_query_qp;
	ibdev->ib_dev.destroy_qp	= mlx4_ib_destroy_qp;
	ibdev->ib_dev.post_send		= mlx4_ib_post_send;
	ibdev->ib_dev.post_recv		= mlx4_ib_post_recv;
	ibdev->ib_dev.create_cq		= mlx4_ib_create_cq;
	ibdev->ib_dev.modify_cq		= mlx4_ib_modify_cq;
	ibdev->ib_dev.resize_cq		= mlx4_ib_resize_cq;
	ibdev->ib_dev.destroy_cq	= mlx4_ib_destroy_cq;
	ibdev->ib_dev.poll_cq		= mlx4_ib_poll_cq;
	ibdev->ib_dev.req_notify_cq	= mlx4_ib_arm_cq;
	ibdev->ib_dev.get_dma_mr	= mlx4_ib_get_dma_mr;
	//ibdev->ib_dev.reg_user_mr	= mlx4_ib_reg_user_mr;
	ibdev->ib_dev.dereg_mr		= mlx4_ib_dereg_mr;
	ibdev->ib_dev.alloc_fast_reg_mr = mlx4_ib_alloc_fast_reg_mr;
	//ibdev->ib_dev.alloc_fast_reg_page_list = mlx4_ib_alloc_fast_reg_page_list;
	//ibdev->ib_dev.free_fast_reg_page_list  = mlx4_ib_free_fast_reg_page_list;
	ibdev->ib_dev.process_mad	= mlx4_ib_process_mad;

	//ibdev->ib_dev.alloc_fmr		= mlx4_ib_fmr_alloc;
	//ibdev->ib_dev.map_phys_fmr	= mlx4_ib_map_phys_fmr;
	//ibdev->ib_dev.unmap_fmr		= mlx4_ib_unmap_fmr;
	//ibdev->ib_dev.dealloc_fmr	= mlx4_ib_fmr_dealloc;

	if (init_node_data(ibdev))
		goto err_map;

	for (i = 0; i < ibdev->num_ports; ++i) {
		pr_info("AT PORT %d\n",i);
		if (mlx4_ib_port_link_layer(&ibdev->ib_dev, i + 1) ==
						IB_LINK_LAYER_ETHERNET) {
		
			// panic("no RoCE");
		} else
				ibdev->counters[i] = -1;
	}

	spin_lock_init(&ibdev->sm_lock);
	mutex_init(&ibdev->cap_mask_mutex);

	if (ib_register_device(&ibdev->ib_dev))
		goto err_counter;

	if (mlx4_ib_mad_init(ibdev)) {
		pr_info("Fail to init mlx4_ib_mad\n");
		goto err_reg;
	}

	ibdev->ib_active = true;
 
	return ibdev;

err_reg:
	ib_unregister_device(&ibdev->ib_dev);

err_counter:
	for (; i; --i)
		if (ibdev->counters[i - 1] != -1)
			mlx4_counter_free(ibdev->dev, ibdev->counters[i - 1]);

err_map:
	iounmap(ibdev->uar_map);

err_uar:
	mlx4_uar_free(dev, &ibdev->priv_uar);

err_pd:
	mlx4_pd_free(dev, ibdev->priv_pdn);

err_dealloc:
	ib_dealloc_device(&ibdev->ib_dev);

	panic("Fail to init mlx4 IB context");
	return NULL;
}

static void mlx4_ib_remove(struct mlx4_dev *dev, void *ibdev_ptr)
{
	struct mlx4_ib_dev *ibdev = ibdev_ptr;
	int p;

	//mlx4_ib_mad_cleanup(ibdev);
	ib_unregister_device(&ibdev->ib_dev);
	iounmap(ibdev->uar_map);
	for (p = 0; p < ibdev->num_ports; ++p)
		if (ibdev->counters[p] != -1)
			mlx4_counter_free(ibdev->dev, ibdev->counters[p]);
	mlx4_foreach_port(p, dev, MLX4_PORT_TYPE_IB)
		mlx4_CLOSE_PORT(dev, p);

	mlx4_uar_free(dev, &ibdev->priv_uar);
	mlx4_pd_free(dev, ibdev->priv_pdn);
	ib_dealloc_device(&ibdev->ib_dev);
}

void handle_port_mgmt_change_event(struct mlx4_eqe *eqe, struct mlx4_ib_dev *dev);

static void mlx4_ib_event(struct mlx4_dev *dev, void *ibdev_ptr,
			  enum mlx4_dev_event event, unsigned long param)
{
	struct ib_event ibev;
	struct mlx4_ib_dev *ibdev = to_mdev((struct ib_device *) ibdev_ptr);
	struct mlx4_eqe *eqe = NULL;
	int p = 0;

	if (event == MLX4_DEV_EVENT_PORT_MGMT_CHANGE)
		eqe = (struct mlx4_eqe *)param;
	else
		p = (int) param;

	switch (event) {
	case MLX4_DEV_EVENT_PORT_UP:
		if (p > ibdev->num_ports)
			return;
		ibev.event = IB_EVENT_PORT_ACTIVE;
		break;

	case MLX4_DEV_EVENT_PORT_DOWN:
		if (p > ibdev->num_ports)
			return;
		ibev.event = IB_EVENT_PORT_ERR;
		break;

	case MLX4_DEV_EVENT_CATASTROPHIC_ERROR:
		ibdev->ib_active = false;
		ibev.event = IB_EVENT_DEVICE_FATAL;
		break;

	case MLX4_DEV_EVENT_PORT_MGMT_CHANGE:
		handle_port_mgmt_change_event(eqe, ibdev);
		return;

	default:
		pr_info("%s(): unhandled event: %d\n", __func__, event);
		WARN_ON(1);
		return;
	}

	ibev.device	      = ibdev_ptr;
	ibev.element.port_num = (u8) p;

	ib_dispatch_event(&ibev);
}

static struct mlx4_interface mlx4_ib_interface = {
	.add		= mlx4_ib_add,
	.remove		= mlx4_ib_remove,
	.event		= mlx4_ib_event,
	.protocol	= MLX4_PROT_IB_IPV6
};

/*
 * XXX:
 * We missed two workqueue threads here.
 */
int __init mlx4_ib_init(void)
{
	int err;

	err = mlx4_register_interface(&mlx4_ib_interface);
	if (err)
		return err;

	return 0;
}
