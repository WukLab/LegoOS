/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
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
#include <rdma/ib_smi.h>

#include <lego/mlx4/cmd.h>
#include <lego/gfp.h>
#include <rdma/ib_pma.h>

#include "mlx4_ib.h"

enum {
	MLX4_IB_VENDOR_CLASS1 = 0x9,
	MLX4_IB_VENDOR_CLASS2 = 0xa
};

/* Counters should be saturate once they reach their maximum value */
#define ASSIGN_32BIT_COUNTER(counter, value) do {\
	if ((value) > (u32)~0U)			 \
		counter = cpu_to_be32((u32)~0U); \
	else					 \
		counter = cpu_to_be32(value);	 \
} while (0)

int mlx4_MAD_IFC(struct mlx4_ib_dev *dev, int mad_ifc_flags,
		 int port, struct ib_wc *in_wc, struct ib_grh *in_grh,
		 void *in_mad, void *response_mad)
{
	struct mlx4_cmd_mailbox *inmailbox, *outmailbox;
	void *inbox;
	int err;
	u32 in_modifier = port;
	u8 op_modifier = 0;

	inmailbox = mlx4_alloc_cmd_mailbox(dev->dev);
	if (IS_ERR(inmailbox))
		return PTR_ERR(inmailbox);
	inbox = inmailbox->buf;

	outmailbox = mlx4_alloc_cmd_mailbox(dev->dev);
	if (IS_ERR(outmailbox)) {
		mlx4_free_cmd_mailbox(dev->dev, inmailbox);
		return PTR_ERR(outmailbox);
	}

	memcpy(inbox, in_mad, 256);

	/*
	 * Key check traps can't be generated unless we have in_wc to
	 * tell us where to send the trap.
	 */
	if ((mad_ifc_flags & MLX4_MAD_IFC_IGNORE_MKEY) || !in_wc)
		op_modifier |= 0x1;
	if ((mad_ifc_flags & MLX4_MAD_IFC_IGNORE_BKEY) || !in_wc)
		op_modifier |= 0x2;
	if (mlx4_is_mfunc(dev->dev) &&
	    (mad_ifc_flags & MLX4_MAD_IFC_NET_VIEW || in_wc))
		op_modifier |= 0x8;

	if (in_wc) {
		struct {
			__be32		my_qpn;
			u32		reserved1;
			__be32		rqpn;
			u8		sl;
			u8		g_path;
			u16		reserved2[2];
			__be16		pkey;
			u32		reserved3[11];
			u8		grh[40];
		} *ext_info;

		memset(inbox + 256, 0, 256);
		ext_info = inbox + 256;

		ext_info->my_qpn = cpu_to_be32(in_wc->qp->qp_num);
		ext_info->rqpn   = cpu_to_be32(in_wc->src_qp);
		ext_info->sl     = in_wc->sl << 4;
		ext_info->g_path = in_wc->dlid_path_bits |
			(in_wc->wc_flags & IB_WC_GRH ? 0x80 : 0);
		ext_info->pkey   = cpu_to_be16(in_wc->pkey_index);

		if (in_grh)
			memcpy(ext_info->grh, in_grh, 40);

		op_modifier |= 0x4;

		in_modifier |= in_wc->slid << 16;
	}

	err = mlx4_cmd_box(dev->dev, inmailbox->dma, outmailbox->dma, in_modifier,
			   mlx4_is_master(dev->dev) ? (op_modifier & ~0x8) : op_modifier,
			   MLX4_CMD_MAD_IFC, MLX4_CMD_TIME_CLASS_C);

	if (!err)
		memcpy(response_mad, outmailbox->buf, 256);

	mlx4_free_cmd_mailbox(dev->dev, inmailbox);
	mlx4_free_cmd_mailbox(dev->dev, outmailbox);

	return err;
}

static void update_sm_ah(struct mlx4_ib_dev *dev, u8 port_num, u16 lid, u8 sl)
{
	struct ib_ah *new_ah;
	struct ib_ah_attr ah_attr;
	unsigned long flags;

	if (!dev->send_agent[port_num - 1][0])
		return;

	memset(&ah_attr, 0, sizeof ah_attr);
	ah_attr.dlid     = lid;
	ah_attr.sl       = sl;
	ah_attr.port_num = port_num;

	new_ah = ib_create_ah(dev->send_agent[port_num - 1][0]->qp->pd,
			      &ah_attr);
	if (IS_ERR(new_ah))
		return;

	spin_lock_irqsave(&dev->sm_lock, flags);
	if (dev->sm_ah[port_num - 1])
		ib_destroy_ah(dev->sm_ah[port_num - 1]);
	dev->sm_ah[port_num - 1] = new_ah;
	spin_unlock_irqrestore(&dev->sm_lock, flags);
}

void mlx4_ib_dispatch_event(struct mlx4_ib_dev *dev, u8 port_num,
			    enum ib_event_type type)
{
	struct ib_event event;

	event.device		= &dev->ib_dev;
	event.element.port_num	= port_num;
	event.event		= type;

	ib_dispatch_event(&event);
}

static void handle_client_rereg_event(struct mlx4_ib_dev *dev, u8 port_num)
{
	mlx4_ib_dispatch_event(dev, port_num, IB_EVENT_CLIENT_REREGISTER);
}

static void handle_lid_change_event(struct mlx4_ib_dev *dev, u8 port_num)
{
	mlx4_ib_dispatch_event(dev, port_num, IB_EVENT_LID_CHANGE);
}

static void __propagate_pkey_ev(struct mlx4_ib_dev *dev, int port_num,
				int block, u32 change_bitmap)
{
	BUG();
}

void mlx4_ib_update_cache_on_guid_change(struct mlx4_ib_dev *dev, int block_num,
					 u8 port_num, u8 *p_data)
{
	BUG();
}

void mlx4_ib_notify_slaves_on_guid_change(struct mlx4_ib_dev *dev,
					  int block_num, u8 port_num,
					  u8 *p_data)
{
	BUG();
}

/*
 * Snoop SM MADs for port info, GUID info, and  P_Key table sets, so we can
 * synthesize LID change, Client-Rereg, GID change, and P_Key change events.
 */
static void smp_snoop(struct ib_device *ibdev, u8 port_num, struct ib_mad *mad,
				u16 prev_lid)
{
	struct ib_port_info *pinfo;
	u16 lid;
	__be16 *base;
	u32 bn, pkey_change_bitmap;
	int i;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);

	pr_debug("%s(): checkme!\n", __func__);
	if ((mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	     mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) &&
	    mad->mad_hdr.method == IB_MGMT_METHOD_SET)
		switch (mad->mad_hdr.attr_id) {
		case IB_SMP_ATTR_PORT_INFO:
			pinfo = (struct ib_port_info *) ((struct ib_smp *) mad)->data;
			lid = be16_to_cpu(pinfo->lid);

			update_sm_ah(dev, port_num,
				     be16_to_cpu(pinfo->sm_lid),
				     pinfo->neighbormtu_mastersmsl & 0xf);

			if (pinfo->clientrereg_resv_subnetto & 0x80)
				handle_client_rereg_event(dev, port_num);

			if (prev_lid != lid)
				handle_lid_change_event(dev, port_num);
			break;

		case IB_SMP_ATTR_PKEY_TABLE:
			if (!mlx4_is_mfunc(dev->dev)) {
				mlx4_ib_dispatch_event(dev, port_num,
						       IB_EVENT_PKEY_CHANGE);
				break;
			}

			/* at this point, we are running in the master.
			 * Slaves do not receive SMPs.
			 */
			bn  = be32_to_cpu(((struct ib_smp *)mad)->attr_mod) & 0xFFFF;
			base = (__be16 *) &(((struct ib_smp *)mad)->data[0]);
			pkey_change_bitmap = 0;
			for (i = 0; i < 32; i++) {
				pr_debug("PKEY[%d] = x%x\n",
					 i + bn*32, be16_to_cpu(base[i]));
				if (be16_to_cpu(base[i]) !=
				    dev->pkeys.phys_pkey_cache[port_num - 1][i + bn*32]) {
					pkey_change_bitmap |= (1 << i);
					dev->pkeys.phys_pkey_cache[port_num - 1][i + bn*32] =
						be16_to_cpu(base[i]);
				}
			}
			pr_debug("PKEY Change event: port=%d, "
				 "block=0x%x, change_bitmap=0x%x\n",
				 port_num, bn, pkey_change_bitmap);

			if (pkey_change_bitmap) {
				mlx4_ib_dispatch_event(dev, port_num,
						       IB_EVENT_PKEY_CHANGE);
				if (!dev->sriov.is_going_down)
					__propagate_pkey_ev(dev, port_num, bn,
							    pkey_change_bitmap);
			}
			break;

		case IB_SMP_ATTR_GUID_INFO:
			/* paravirtualized master's guid is guid 0 -- does not change */
			if (!mlx4_is_master(dev->dev))
				mlx4_ib_dispatch_event(dev, port_num,
						       IB_EVENT_GID_CHANGE);
			/*if master, notify relevant slaves*/
			if (mlx4_is_master(dev->dev) &&
			    !dev->sriov.is_going_down) {
				bn = be32_to_cpu(((struct ib_smp *)mad)->attr_mod);
				mlx4_ib_update_cache_on_guid_change(dev, bn, port_num,
								    (u8 *)(&((struct ib_smp *)mad)->data));
				mlx4_ib_notify_slaves_on_guid_change(dev, bn, port_num,
								     (u8 *)(&((struct ib_smp *)mad)->data));
			}
			break;

		default:
			break;
		}
}

static void node_desc_override(struct ib_device *dev,
			       struct ib_mad *mad)
{
	unsigned long flags;

	if ((mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	     mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) &&
	    mad->mad_hdr.method == IB_MGMT_METHOD_GET_RESP &&
	    mad->mad_hdr.attr_id == IB_SMP_ATTR_NODE_DESC) {
		spin_lock_irqsave(&to_mdev(dev)->sm_lock, flags);
		memcpy(((struct ib_smp *) mad)->data, dev->node_desc, 64);
		spin_unlock_irqrestore(&to_mdev(dev)->sm_lock, flags);
	}
}

static void forward_trap(struct mlx4_ib_dev *dev, u8 port_num, struct ib_mad *mad)
{
	int qpn = mad->mad_hdr.mgmt_class != IB_MGMT_CLASS_SUBN_LID_ROUTED;
	struct ib_mad_send_buf *send_buf;
	struct ib_mad_agent *agent = dev->send_agent[port_num - 1][qpn];
	int ret;
	unsigned long flags;

	if (agent) {
		send_buf = ib_create_send_mad(agent, qpn, 0, 0, IB_MGMT_MAD_HDR,
					      IB_MGMT_MAD_DATA, GFP_ATOMIC);
		if (IS_ERR(send_buf))
			return;
		/*
		 * We rely here on the fact that MLX QPs don't use the
		 * address handle after the send is posted (this is
		 * wrong following the IB spec strictly, but we know
		 * it's OK for our devices).
		 */
		spin_lock_irqsave(&dev->sm_lock, flags);
		memcpy(send_buf->mad, mad, sizeof *mad);
		if ((send_buf->ah = dev->sm_ah[port_num - 1]))
			ret = ib_post_send_mad(send_buf, NULL);
		else
			ret = -EINVAL;
		spin_unlock_irqrestore(&dev->sm_lock, flags);

		if (ret)
			ib_free_send_mad(send_buf);
	}
}

static int ib_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	u16 slid, prev_lid = 0;
	int err;
	struct ib_port_attr pattr;

	if (in_wc && in_wc->qp->qp_num) {
		pr_debug("received MAD: slid:%d sqpn:%d "
			"dlid_bits:%d dqpn:%d wc_flags:0x%x, cls %x, mtd %x, atr %x\n",
			in_wc->slid, in_wc->src_qp,
			in_wc->dlid_path_bits,
			in_wc->qp->qp_num,
			in_wc->wc_flags,
			in_mad->mad_hdr.mgmt_class, in_mad->mad_hdr.method,
			be16_to_cpu(in_mad->mad_hdr.attr_id));
		if (in_wc->wc_flags & IB_WC_GRH) {
			pr_debug("sgid_hi:0x%016llx sgid_lo:0x%016llx\n",
				 be64_to_cpu(in_grh->sgid.global.subnet_prefix),
				 be64_to_cpu(in_grh->sgid.global.interface_id));
			pr_debug("dgid_hi:0x%016llx dgid_lo:0x%016llx\n",
				 be64_to_cpu(in_grh->dgid.global.subnet_prefix),
				 be64_to_cpu(in_grh->dgid.global.interface_id));
		}
	}

	slid = in_wc ? in_wc->slid : be16_to_cpu(IB_LID_PERMISSIVE);

	if (in_mad->mad_hdr.method == IB_MGMT_METHOD_TRAP && slid == 0) {
		forward_trap(to_mdev(ibdev), port_num, in_mad);
		return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;
	}

	if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	    in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) {
		if (in_mad->mad_hdr.method   != IB_MGMT_METHOD_GET &&
		    in_mad->mad_hdr.method   != IB_MGMT_METHOD_SET &&
		    in_mad->mad_hdr.method   != IB_MGMT_METHOD_TRAP_REPRESS)
			return IB_MAD_RESULT_SUCCESS;

		/*
		 * Don't process SMInfo queries -- the SMA can't handle them.
		 */
		if (in_mad->mad_hdr.attr_id == IB_SMP_ATTR_SM_INFO)
			return IB_MAD_RESULT_SUCCESS;
	} else if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_PERF_MGMT ||
		   in_mad->mad_hdr.mgmt_class == MLX4_IB_VENDOR_CLASS1   ||
		   in_mad->mad_hdr.mgmt_class == MLX4_IB_VENDOR_CLASS2   ||
		   in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_CONG_MGMT) {
		if (in_mad->mad_hdr.method  != IB_MGMT_METHOD_GET &&
		    in_mad->mad_hdr.method  != IB_MGMT_METHOD_SET)
			return IB_MAD_RESULT_SUCCESS;
	} else
		return IB_MAD_RESULT_SUCCESS;

	if ((in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	     in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) &&
	    in_mad->mad_hdr.method == IB_MGMT_METHOD_SET &&
	    in_mad->mad_hdr.attr_id == IB_SMP_ATTR_PORT_INFO &&
	    !ib_query_port(ibdev, port_num, &pattr))
		prev_lid = pattr.lid;

	err = mlx4_MAD_IFC(to_mdev(ibdev),
			   (mad_flags & IB_MAD_IGNORE_MKEY ? MLX4_MAD_IFC_IGNORE_MKEY : 0) |
			   (mad_flags & IB_MAD_IGNORE_BKEY ? MLX4_MAD_IFC_IGNORE_BKEY : 0) |
			   MLX4_MAD_IFC_NET_VIEW,
			   port_num, in_wc, in_grh, in_mad, out_mad);
	if (err) {
		pr_info("%s(): MAD_IFC fails\n", __func__);
		return IB_MAD_RESULT_FAILURE;
	}

	if (!out_mad->mad_hdr.status) {
		if (!(to_mdev(ibdev)->dev->caps.flags & MLX4_DEV_CAP_FLAG_PORT_MNG_CHG_EV))
			smp_snoop(ibdev, port_num, in_mad, prev_lid);
		/* slaves get node desc from FW */
		if (!mlx4_is_slave(to_mdev(ibdev)->dev))
			node_desc_override(ibdev, out_mad);
	}

	/* set return bit in status of directed route responses */
	if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		out_mad->mad_hdr.status |= cpu_to_be16(1 << 15);

	if (in_mad->mad_hdr.method == IB_MGMT_METHOD_TRAP_REPRESS)
		/* no response for trap repress */
		return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;

	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
}

static int iboe_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	BUG();
}

int mlx4_ib_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	switch (rdma_port_get_link_layer(ibdev, port_num)) {
	case IB_LINK_LAYER_INFINIBAND:
		return ib_process_mad(ibdev, mad_flags, port_num, in_wc,
				      in_grh, in_mad, out_mad);
	case IB_LINK_LAYER_ETHERNET:
		return iboe_process_mad(ibdev, mad_flags, port_num, in_wc,
					  in_grh, in_mad, out_mad);
	default:
		return -EINVAL;
	}
}

static void send_handler(struct ib_mad_agent *agent,
			 struct ib_mad_send_wc *mad_send_wc)
{
	if (mad_send_wc->send_buf->context[0])
		ib_destroy_ah(mad_send_wc->send_buf->context[0]);
	ib_free_send_mad(mad_send_wc->send_buf);
}

int mlx4_ib_mad_init(struct mlx4_ib_dev *dev)
{
	struct ib_mad_agent *agent;
	int p, q;
	int ret;
	enum rdma_link_layer ll;

	for (p = 0; p < dev->num_ports; ++p) {
		ll = rdma_port_get_link_layer(&dev->ib_dev, p + 1);
		for (q = 0; q <= 1; ++q) {
			if (ll == IB_LINK_LAYER_INFINIBAND) {
				agent = ib_register_mad_agent(&dev->ib_dev, p + 1,
							      q ? IB_QPT_GSI : IB_QPT_SMI,
							      NULL, 0, send_handler,
							      NULL, NULL);
				if (IS_ERR(agent)) {
					ret = PTR_ERR(agent);
					goto err;
				}
				dev->send_agent[p][q] = agent;
			} else
				dev->send_agent[p][q] = NULL;
		}
	}

	return 0;

err:
	for (p = 0; p < dev->num_ports; ++p)
		for (q = 0; q <= 1; ++q)
			if (dev->send_agent[p][q])
				ib_unregister_mad_agent(dev->send_agent[p][q]);

	return ret;
}

void mlx4_ib_mad_cleanup(struct mlx4_ib_dev *dev)
{
	struct ib_mad_agent *agent;
	int p, q;

	for (p = 0; p < dev->num_ports; ++p) {
		for (q = 0; q <= 1; ++q) {
			agent = dev->send_agent[p][q];
			if (agent) {
				dev->send_agent[p][q] = NULL;
				ib_unregister_mad_agent(agent);
			}
		}

		if (dev->sm_ah[p])
			ib_destroy_ah(dev->sm_ah[p]);
	}
}

void handle_port_mgmt_change_event(struct mlx4_eqe *eqe, struct mlx4_ib_dev *dev)
{
	u8 port = eqe->event.port_mgmt_change.port;
	u32 changed_attr;

	switch (eqe->subtype) {
	case MLX4_DEV_PMC_SUBTYPE_PORT_INFO:
		changed_attr = be32_to_cpu(eqe->event.port_mgmt_change.params.port_info.changed_attr);

		/* Update the SM ah - This should be done before handling
		   the other changed attributes so that MADs can be sent to the SM */
		if (changed_attr & MSTR_SM_CHANGE_MASK) {
			u16 lid = be16_to_cpu(eqe->event.port_mgmt_change.params.port_info.mstr_sm_lid);
			u8 sl = eqe->event.port_mgmt_change.params.port_info.mstr_sm_sl & 0xf;

			pr_info("update sm ah\n");
			update_sm_ah(dev, port, lid, sl);
		}

		/* Check if it is a lid change event */
		if (changed_attr & MLX4_EQ_PORT_INFO_LID_CHANGE_MASK) {
			pr_info("lid change\n");
			handle_lid_change_event(dev, port);
		}

		/* Generate GUID changed event */
		if (changed_attr & MLX4_EQ_PORT_INFO_GID_PFX_CHANGE_MASK) {
			pr_info("gid change 1\n");
			mlx4_ib_dispatch_event(dev, port, IB_EVENT_GID_CHANGE);
		}

		if (changed_attr & MLX4_EQ_PORT_INFO_CLIENT_REREG_MASK) {
			pr_info("rereg \n");
			handle_client_rereg_event(dev, port);
		}
		break;

	case MLX4_DEV_PMC_SUBTYPE_PKEY_TABLE:
		pr_info("pkey change\n");
		mlx4_ib_dispatch_event(dev, port, IB_EVENT_PKEY_CHANGE);
		break;
	case MLX4_DEV_PMC_SUBTYPE_GUID_INFO:
		/* paravirtualized master's guid is guid 0 -- does not change */
		if (!mlx4_is_master(dev->dev)) {
			pr_info("gid change 2\n");
			mlx4_ib_dispatch_event(dev, port, IB_EVENT_GID_CHANGE);
		}
		break;
	default:
		pr_warn("Unsupported subtype 0x%x for "
			"Port Management Change event\n", eqe->subtype);
	}
}
