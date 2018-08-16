/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc. All rights reserved.
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

#define pr_fmt(fmt) "mlx4_core: " fmt

#include <lego/init.h>
#include <lego/errno.h>
#include <lego/pci.h>
#include <lego/dma-mapping.h>
#include <lego/slab.h>
#include <lego/mlx4/driver.h>
#include <lego/mlx4/doorbell.h>

#include "mlx4.h"
#include "fw.h"
#include "icm.h"

/* enable #num_vfs functions if num_vfs > 0 */
static const int num_vfs = 0;

#ifdef CONFIG_MLX4_DEBUG
int mlx4_debug_level = 0;
#endif

#ifdef CONFIG_PCI_MSI

static int msi_x = 1;
//module_param(msi_x, int, 0444);
//MODULE_PARM_DESC(msi_x, "attempt to use MSI-X if nonzero");

#else /* CONFIG_PCI_MSI */

#define msi_x (0)

#endif /* CONFIG_PCI_MSI */

//static char mlx4_version[] __devinitdata =
//	DRV_NAME ": Mellanox ConnectX core driver v"
//	DRV_VERSION " (" DRV_RELDATE ")\n";

static struct mlx4_profile default_profile = {
	.num_qp		= 1 << 17,
	.num_srq	= 1 << 16,
	.rdmarc_per_qp	= 1 << 4,
	.num_cq		= 1 << 16,
	.num_mcg	= 1 << 13,
	.num_mpt	= 1 << 17,
	.num_mtt	= 1 << 20,
};

static int log_num_mac = 2;
//module_param_named(log_num_mac, log_num_mac, int, 0444);
//MODULE_PARM_DESC(log_num_mac, "Log2 max number of MACs per ETH port (1-7)");

static int log_num_vlan;
//module_param_named(log_num_vlan, log_num_vlan, int, 0444);
//MODULE_PARM_DESC(log_num_vlan, "Log2 max number of VLANs per ETH port (0-7)");
/* Log2 max number of VLANs per ETH port (0-7) */
#define MLX4_LOG_NUM_VLANS 7

static int use_prio = 0;
//module_param_named(use_prio, use_prio, bool, 0444);
//MODULE_PARM_DESC(use_prio, "Enable steering by VLAN priority on ETH ports "
//		  "(0/1, default 0)");

static int log_mtts_per_seg = ilog2(MLX4_MTT_ENTRY_PER_SEG);
//module_param_named(log_mtts_per_seg, log_mtts_per_seg, int, 0444);
//MODULE_PARM_DESC(log_mtts_per_seg, "Log2 number of MTT entries per segment (1-7)");

int mlx4_check_port_params(struct mlx4_dev *dev,
			   enum mlx4_port_type *port_type)
{
	int i;

	for (i = 0; i < dev->caps.num_ports - 1; i++) {
		if (port_type[i] != port_type[i + 1]) {
			if (!(dev->caps.flags & MLX4_DEV_CAP_FLAG_DPDP)) {
				mlx4_err(dev, "Only same port types supported "
					 "on this HCA, aborting.\n");
				return -EINVAL;
			}
			if (port_type[i] == MLX4_PORT_TYPE_ETH &&
			    port_type[i + 1] == MLX4_PORT_TYPE_IB)
				return -EINVAL;
		}
	}

	for (i = 0; i < dev->caps.num_ports; i++) {
		if (!(port_type[i] & dev->caps.supported_type[i+1])) {
			mlx4_err(dev, "Requested port type for port %d is not "
				      "supported on this HCA\n", i + 1);
			return -EINVAL;
		}
	}
	return 0;
}

static void mlx4_set_port_mask(struct mlx4_dev *dev)
{
	int i;

	for (i = 1; i <= dev->caps.num_ports; ++i)
		dev->caps.port_mask[i] = dev->caps.port_type[i];
}

static int mlx4_dev_cap(struct mlx4_dev *dev, struct mlx4_dev_cap *dev_cap)
{
	int err;
	int i;

	err = mlx4_QUERY_DEV_CAP(dev, dev_cap);
	if (err) {
		mlx4_err(dev, "QUERY_DEV_CAP command failed, aborting.\n");
		return err;
	}

	if (dev_cap->min_page_sz > PAGE_SIZE) {
		mlx4_err(dev, "HCA minimum page size of %d bigger than "
			 "kernel PAGE_SIZE of %ld, aborting.\n",
			 dev_cap->min_page_sz, PAGE_SIZE);
		return -ENODEV;
	}
	if (dev_cap->num_ports > MLX4_MAX_PORTS) {
		mlx4_err(dev, "HCA has %d ports, but we only support %d, "
			 "aborting.\n",
			 dev_cap->num_ports, MLX4_MAX_PORTS);
		return -ENODEV;
	}

	if (dev_cap->uar_size > pci_resource_len(dev->pdev, 2)) {
		mlx4_err(dev, "HCA reported UAR size of 0x%x bigger than "
			 "PCI resource 2 size of 0x%llx, aborting.\n",
			 dev_cap->uar_size,
			 (unsigned long long) pci_resource_len(dev->pdev, 2));
		return -ENODEV;
	}

	dev->caps.num_ports	     = dev_cap->num_ports;
	for (i = 1; i <= dev->caps.num_ports; ++i) {
		dev->caps.vl_cap[i]	    = dev_cap->max_vl[i];
		dev->caps.ib_mtu_cap[i]	    = dev_cap->ib_mtu[i];
		dev->caps.gid_table_len[i]  = dev_cap->max_gids[i];
		dev->caps.pkey_table_len[i] = dev_cap->max_pkeys[i];
		dev->caps.port_width_cap[i] = dev_cap->max_port_width[i];
		dev->caps.eth_mtu_cap[i]    = dev_cap->eth_mtu[i];
		dev->caps.def_mac[i]        = dev_cap->def_mac[i];
		dev->caps.supported_type[i] = dev_cap->supported_port_types[i];
		dev->caps.trans_type[i]	    = dev_cap->trans_type[i];
		dev->caps.vendor_oui[i]     = dev_cap->vendor_oui[i];
		dev->caps.wavelength[i]     = dev_cap->wavelength[i];
		dev->caps.trans_code[i]     = dev_cap->trans_code[i];
	}

	dev->caps.num_uars	     = dev_cap->uar_size / PAGE_SIZE;
	dev->caps.local_ca_ack_delay = dev_cap->local_ca_ack_delay;
	dev->caps.bf_reg_size	     = dev_cap->bf_reg_size;
	dev->caps.bf_regs_per_page   = dev_cap->bf_regs_per_page;
	dev->caps.max_sq_sg	     = dev_cap->max_sq_sg;
	dev->caps.max_rq_sg	     = dev_cap->max_rq_sg;
	dev->caps.max_wqes	     = dev_cap->max_qp_sz;
	dev->caps.max_qp_init_rdma   = dev_cap->max_requester_per_qp;
	dev->caps.max_srq_wqes	     = dev_cap->max_srq_sz;
	dev->caps.max_srq_sge	     = dev_cap->max_rq_sg - 1;
	dev->caps.reserved_srqs	     = dev_cap->reserved_srqs;
	dev->caps.max_sq_desc_sz     = dev_cap->max_sq_desc_sz;
	dev->caps.max_rq_desc_sz     = dev_cap->max_rq_desc_sz;
	dev->caps.num_qp_per_mgm     = MLX4_QP_PER_MGM;
	/*
	 * Subtract 1 from the limit because we need to allocate a
	 * spare CQE so the HCA HW can tell the difference between an
	 * empty CQ and a full CQ.
	 */
	dev->caps.max_cqes	     = dev_cap->max_cq_sz - 1;
	dev->caps.reserved_cqs	     = dev_cap->reserved_cqs;
	dev->caps.reserved_eqs	     = dev_cap->reserved_eqs;
	dev->caps.mtts_per_seg	     = 1 << log_mtts_per_seg;
	dev->caps.reserved_mtts	     = DIV_ROUND_UP(dev_cap->reserved_mtts,
						    dev->caps.mtts_per_seg);
	dev->caps.reserved_mrws	     = dev_cap->reserved_mrws;
	dev->caps.reserved_uars	     = dev_cap->reserved_uars;
	dev->caps.reserved_pds	     = dev_cap->reserved_pds;
//	dev->caps.reserved_xrcds     = (dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC) ?
//					dev_cap->reserved_xrcds : 0;
//	dev->caps.max_xrcds          = (dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC) ?
//					dev_cap->max_xrcds : 0;
	dev->caps.mtt_entry_sz	     = dev->caps.mtts_per_seg * dev_cap->mtt_entry_sz;
	dev->caps.max_msg_sz         = dev_cap->max_msg_sz;
	dev->caps.page_size_cap	     = ~(u32) (dev_cap->min_page_sz - 1);
	dev->caps.flags		     = dev_cap->flags;
	dev->caps.bmme_flags	     = dev_cap->bmme_flags;
	dev->caps.reserved_lkey	     = dev_cap->reserved_lkey;
	dev->caps.stat_rate_support  = dev_cap->stat_rate_support;
	dev->caps.max_gso_sz	     = dev_cap->max_gso_sz;

	dev->caps.log_num_macs  = log_num_mac;
	dev->caps.log_num_vlans = MLX4_LOG_NUM_VLANS;
	dev->caps.log_num_prios = use_prio ? 3 : 0;

	for (i = 1; i <= dev->caps.num_ports; ++i) {
		if (dev->caps.supported_type[i] != MLX4_PORT_TYPE_ETH)
			dev->caps.port_type[i] = MLX4_PORT_TYPE_IB;
		else
			dev->caps.port_type[i] = MLX4_PORT_TYPE_ETH;
		dev->caps.possible_type[i] = dev->caps.port_type[i];
		mlx4_priv(dev)->sense.sense_allowed[i] =
			dev->caps.supported_type[i] == MLX4_PORT_TYPE_AUTO;

		if (dev->caps.log_num_macs > dev_cap->log_max_macs[i]) {
			dev->caps.log_num_macs = dev_cap->log_max_macs[i];
			mlx4_warn(dev, "Requested number of MACs is too much "
				  "for port %d, reducing to %d.\n",
				  i, 1 << dev->caps.log_num_macs);
		}
		if (dev->caps.log_num_vlans > dev_cap->log_max_vlans[i]) {
			dev->caps.log_num_vlans = dev_cap->log_max_vlans[i];
			mlx4_warn(dev, "Requested number of VLANs is too much "
				  "for port %d, reducing to %d.\n",
				  i, 1 << dev->caps.log_num_vlans);
		}
	}

	mlx4_set_port_mask(dev);

	dev->caps.max_counters = 1 << ilog2(dev_cap->max_counters);

	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW] = dev_cap->reserved_qps;
	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_ETH_ADDR] =
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_ADDR] =
		(1 << dev->caps.log_num_macs) *
		(1 << dev->caps.log_num_vlans) *
		(1 << dev->caps.log_num_prios) *
		dev->caps.num_ports;
	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_EXCH] = MLX4_NUM_FEXCH;

	dev->caps.reserved_qps = dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_ETH_ADDR] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_ADDR] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_EXCH];

	return 0;
}

static int mlx4_load_fw(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;

	priv->fw.fw_icm = mlx4_alloc_icm(dev, priv->fw.fw_pages,
					 __GFP_HIGHMEM | __GFP_IO | ___GFP_NOWARN, 0);
					 //GFP_HIGHUSER | __GFP_NOWARN, 0);
	if (!priv->fw.fw_icm) {
		mlx4_err(dev, "Couldn't allocate FW area, aborting.\n");
		return -ENOMEM;
	}

	err = mlx4_MAP_FA(dev, priv->fw.fw_icm);
	if (err) {
		mlx4_err(dev, "MAP_FA command failed, aborting.\n");
		goto err_free;
	}

	err = mlx4_RUN_FW(dev);
	if (err) {
		mlx4_err(dev, "RUN_FW command failed, aborting.\n");
		goto err_unmap_fa;
	}

	return 0;

err_unmap_fa:
	mlx4_UNMAP_FA(dev);

err_free:
	mlx4_free_icm(dev, priv->fw.fw_icm, 0);
	return err;
}

static int mlx4_init_cmpt_table(struct mlx4_dev *dev, u64 cmpt_base,
				int cmpt_entry_sz)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;

	err = mlx4_init_icm_table(dev, &priv->qp_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_QP *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err)
		goto err;

#if 0
	err = mlx4_init_icm_table(dev, &priv->srq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_SRQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_srqs,
				  dev->caps.reserved_srqs, 0, 0);
	if (err)
		goto err_qp;
#endif

	err = mlx4_init_icm_table(dev, &priv->cq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_CQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_cqs,
				  dev->caps.reserved_cqs, 0, 0);
	if (err)
		goto err_srq;

	err = mlx4_init_icm_table(dev, &priv->eq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_EQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz,
				  dev->caps.num_eqs, dev->caps.num_eqs, 0, 0);
	if (err)
		goto err_cq;

	return 0;

err_cq:
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table);

err_srq:
//	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table);

	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table);

err:
	return err;
}

static int mlx4_init_icm(struct mlx4_dev *dev, struct mlx4_dev_cap *dev_cap,
			 struct mlx4_init_hca_param *init_hca, u64 icm_size)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u64 aux_pages;
	int err;

	err = mlx4_SET_ICM_SIZE(dev, icm_size, &aux_pages);
	if (err) {
		mlx4_err(dev, "SET_ICM_SIZE command failed, aborting.\n");
		return err;
	}

	mlx4_dbg(dev, "%lld KB of HCA context requires %lld KB aux memory.\n",
		 (unsigned long long) icm_size >> 10,
		 (unsigned long long) aux_pages << 2);

	priv->fw.aux_icm = mlx4_alloc_icm(dev, aux_pages,
					 __GFP_HIGHMEM | __GFP_IO | ___GFP_NOWARN, 0);
					 // GFP_HIGHUSER | __GFP_NOWARN, 0);
	if (!priv->fw.aux_icm) {
		mlx4_err(dev, "Couldn't allocate aux memory, aborting.\n");
		return -ENOMEM;
	}

	err = mlx4_MAP_ICM_AUX(dev, priv->fw.aux_icm);
	if (err) {
		mlx4_err(dev, "MAP_ICM_AUX command failed, aborting.\n");
		goto err_free_aux;
	}

	err = mlx4_init_cmpt_table(dev, init_hca->cmpt_base, dev_cap->cmpt_entry_sz);
	if (err) {
		mlx4_err(dev, "Failed to map cMPT context memory, aborting.\n");
		goto err_unmap_aux;
	}

	err = mlx4_init_icm_table(dev, &priv->eq_table.table,
				  init_hca->eqc_base, dev_cap->eqc_entry_sz,
				  dev->caps.num_eqs, dev->caps.num_eqs,
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map EQ context memory, aborting.\n");
		goto err_unmap_cmpt;
	}

	/*
	 * Reserved MTT entries must be aligned up to a cacheline
	 * boundary, since the FW will write to them, while the driver
	 * writes to all other MTT entries. (The variable
	 * dev->caps.mtt_entry_sz below is really the MTT segment
	 * size, not the raw entry size)
	 */
	dev->caps.reserved_mtts =
		ALIGN(dev->caps.reserved_mtts * dev->caps.mtt_entry_sz,
		      dma_get_cache_alignment()) / dev->caps.mtt_entry_sz;

	err = mlx4_init_icm_table(dev, &priv->mr_table.mtt_table,
				  init_hca->mtt_base,
				  dev->caps.mtt_entry_sz,
				  dev->caps.num_mtts,
				  dev->caps.reserved_mtts, 1, 0);
	if (err) {
		mlx4_err(dev, "Failed to map MTT context memory, aborting.\n");
		goto err_unmap_eq;
	}

	err = mlx4_init_icm_table(dev, &priv->mr_table.dmpt_table,
				  init_hca->dmpt_base,
				  dev_cap->dmpt_entry_sz,
				  dev->caps.num_mpts,
				  dev->caps.reserved_mrws, 1, 1);
	if (err) {
		mlx4_err(dev, "Failed to map dMPT context memory, aborting.\n");
		goto err_unmap_mtt;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.qp_table,
				  init_hca->qpc_base,
				  dev_cap->qpc_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map QP context memory, aborting.\n");
		goto err_unmap_dmpt;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.auxc_table,
				  init_hca->auxc_base,
				  dev_cap->aux_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map AUXC context memory, aborting.\n");
		goto err_unmap_qp;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.altc_table,
				  init_hca->altc_base,
				  dev_cap->altc_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map ALTC context memory, aborting.\n");
		goto err_unmap_auxc;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.rdmarc_table,
				  init_hca->rdmarc_base,
				  dev_cap->rdmarc_entry_sz << priv->qp_table.rdmarc_shift,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map RDMARC context memory, aborting\n");
		goto err_unmap_altc;
	}

	err = mlx4_init_icm_table(dev, &priv->cq_table.table,
				  init_hca->cqc_base,
				  dev_cap->cqc_entry_sz,
				  dev->caps.num_cqs,
				  dev->caps.reserved_cqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map CQ context memory, aborting.\n");
		goto err_unmap_rdmarc;
	}

#if 0
	err = mlx4_init_icm_table(dev, &priv->srq_table.table,
				  init_hca->srqc_base,
				  dev_cap->srq_entry_sz,
				  dev->caps.num_srqs,
				  dev->caps.reserved_srqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map SRQ context memory, aborting.\n");
		goto err_unmap_cq;
	}

	/*
	 * It's not strictly required, but for simplicity just map the
	 * whole multicast group table now.  The table isn't very big
	 * and it's a lot easier than trying to track ref counts.
	 */
	err = mlx4_init_icm_table(dev, &priv->mcg_table.table,
				  init_hca->mc_base, MLX4_MGM_ENTRY_SIZE,
				  dev->caps.num_mgms + dev->caps.num_amgms,
				  dev->caps.num_mgms + dev->caps.num_amgms,
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map MCG context memory, aborting.\n");
		goto err_unmap_srq;
	}
#endif

	return 0;

err_unmap_srq:
//	mlx4_cleanup_icm_table(dev, &priv->srq_table.table);

err_unmap_cq:
	mlx4_cleanup_icm_table(dev, &priv->cq_table.table);

err_unmap_rdmarc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.rdmarc_table);

err_unmap_altc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.altc_table);

err_unmap_auxc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.auxc_table);

err_unmap_qp:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.qp_table);

err_unmap_dmpt:
	mlx4_cleanup_icm_table(dev, &priv->mr_table.dmpt_table);

err_unmap_mtt:
	mlx4_cleanup_icm_table(dev, &priv->mr_table.mtt_table);

err_unmap_eq:
	mlx4_cleanup_icm_table(dev, &priv->eq_table.table);

err_unmap_cmpt:
	mlx4_cleanup_icm_table(dev, &priv->eq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table);
//	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table);

err_unmap_aux:
	mlx4_UNMAP_ICM_AUX(dev);

err_free_aux:
	mlx4_free_icm(dev, priv->fw.aux_icm, 0);

	return err;
}

static void mlx4_free_icms(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

//	mlx4_cleanup_icm_table(dev, &priv->mcg_table.table);
//	mlx4_cleanup_icm_table(dev, &priv->srq_table.table);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.rdmarc_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.altc_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.auxc_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.qp_table);
	mlx4_cleanup_icm_table(dev, &priv->mr_table.dmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->mr_table.mtt_table);
	mlx4_cleanup_icm_table(dev, &priv->eq_table.table);
	mlx4_cleanup_icm_table(dev, &priv->eq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table);
//	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table);

	mlx4_UNMAP_ICM_AUX(dev);
	mlx4_free_icm(dev, priv->fw.aux_icm, 0);
}

static int map_bf_area(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	resource_size_t bf_start;
	resource_size_t bf_len;
	int err = 0;

#if 0
XXX
	bf_start = pci_resource_start(dev->pdev, 2) + (dev->caps.num_uars << PAGE_SHIFT);
	bf_len = pci_resource_len(dev->pdev, 2) - (dev->caps.num_uars << PAGE_SHIFT);
	priv->bf_mapping = io_mapping_create_wc(bf_start, bf_len);
	if (!priv->bf_mapping)
		err = -ENOMEM;
#endif
	return err;
}

static void unmap_bf_area(struct mlx4_dev *dev)
{
#if 0
XXX
	if (mlx4_priv(dev)->bf_mapping)
		io_mapping_free(mlx4_priv(dev)->bf_mapping);
#endif
}

static void mlx4_close_hca(struct mlx4_dev *dev)
{
	unmap_bf_area(dev);
	mlx4_CLOSE_HCA(dev, 0);
	mlx4_free_icms(dev);
	mlx4_UNMAP_FA(dev);
	mlx4_free_icm(dev, mlx4_priv(dev)->fw.fw_icm, 0);
}

static int mlx4_init_hca(struct mlx4_dev *dev)
{
	struct mlx4_priv	  *priv = mlx4_priv(dev);
	struct mlx4_adapter	   adapter;
	struct mlx4_dev_cap	   dev_cap;
	struct mlx4_mod_stat_cfg   mlx4_cfg;
	struct mlx4_profile	   profile;
	struct mlx4_init_hca_param init_hca;
	u64 icm_size;
	int err;

	err = mlx4_QUERY_FW(dev);
	if (err) {
		if (err == -EACCES)
			mlx4_info(dev, "non-primary physical function, skipping.\n");
		else
			mlx4_err(dev, "QUERY_FW command failed, aborting.\n");
		return err;
	}

	err = mlx4_load_fw(dev);
	if (err) {
		mlx4_err(dev, "Failed to start FW, aborting.\n");
		return err;
	}

	mlx4_cfg.log_pg_sz_m = 1;
	mlx4_cfg.log_pg_sz = 0;
	err = mlx4_MOD_STAT_CFG(dev, &mlx4_cfg);
	if (err)
		mlx4_warn(dev, "Failed to override log_pg_sz parameter\n");

	err = mlx4_dev_cap(dev, &dev_cap);
	if (err) {
		mlx4_err(dev, "QUERY_DEV_CAP command failed, aborting.\n");
		goto err_stop_fw;
	}

	profile = default_profile;

	icm_size = mlx4_make_profile(dev, &profile, &dev_cap, &init_hca);
	if ((long long) icm_size < 0) {
		err = icm_size;
		goto err_stop_fw;
	}

	if (map_bf_area(dev))
		mlx4_dbg(dev, "Failed to map blue flame area\n");

	init_hca.log_uar_sz = ilog2(dev->caps.num_uars);

	err = mlx4_init_icm(dev, &dev_cap, &init_hca, icm_size);
	if (err)
		goto err_stop_fw;

	err = mlx4_INIT_HCA(dev, &init_hca);
	if (err) {
		mlx4_err(dev, "INIT_HCA command failed, aborting.\n");
		goto err_free_icm;
	}

	err = mlx4_QUERY_ADAPTER(dev, &adapter);
	if (err) {
		mlx4_err(dev, "QUERY_ADAPTER command failed, aborting.\n");
		goto err_close;
	}

	priv->eq_table.inta_pin = adapter.inta_pin;
	memcpy(dev->board_id, adapter.board_id, sizeof dev->board_id);

	return 0;

err_close:
	mlx4_CLOSE_HCA(dev, 0);

err_free_icm:
	mlx4_free_icms(dev);

err_stop_fw:
	unmap_bf_area(dev);
	mlx4_UNMAP_FA(dev);
	mlx4_free_icm(dev, priv->fw.fw_icm, 0);

	return err;
}

static int mlx4_init_counters_table(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int nent;

	if (!(dev->caps.flags & MLX4_DEV_CAP_FLAG_COUNTERS))
		return -ENOENT;

	nent = dev->caps.max_counters;
	return mlx4_bitmap_init(&priv->counters_bitmap, nent, nent - 1, 0, 0);
}

static void mlx4_cleanup_counters_table(struct mlx4_dev *dev)
{
	mlx4_bitmap_cleanup(&mlx4_priv(dev)->counters_bitmap);
}

int mlx4_counter_alloc(struct mlx4_dev *dev, u32 *idx)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	if (!(dev->caps.flags & MLX4_DEV_CAP_FLAG_COUNTERS))
		return -ENOENT;

	*idx = mlx4_bitmap_alloc(&priv->counters_bitmap);
	if (*idx == -1)
		return -ENOMEM;

	return 0;
}

void mlx4_counter_free(struct mlx4_dev *dev, u32 idx)
{
	mlx4_bitmap_free(&mlx4_priv(dev)->counters_bitmap, idx);
	return;
}

static int mlx4_setup_hca(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int port;
	__be32 ib_port_default_caps;

	//pr_debug("%s enter\n",__func__);

	err = mlx4_init_uar_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "user access region table, aborting.\n");
		return err;
	}

	err = mlx4_uar_alloc(dev, &priv->driver_uar);
	if (err) {
		mlx4_err(dev, "Failed to allocate driver access region, "
			 "aborting.\n");
		goto err_uar_table_free;
	}

	priv->kar = ioremap((phys_addr_t) priv->driver_uar.pfn << PAGE_SHIFT, PAGE_SIZE);
	if (!priv->kar) {
		mlx4_err(dev, "Couldn't map kernel access region, "
			 "aborting.\n");
		err = -ENOMEM;
		goto err_uar_free;
	}

	err = mlx4_init_pd_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "protection domain table, aborting.\n");
		goto err_kar_unmap;
	}

#if 0
	err = mlx4_init_xrcd_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "reliable connection domain table, aborting.\n");
		goto err_pd_table_free;
	}
#endif

	err = mlx4_init_mr_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "memory region table, aborting.\n");
		goto err_xrcd_table_free;
	}

	err = mlx4_init_eq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "event queue table, aborting.\n");
		goto err_mr_table_free;
	}

	err = mlx4_cmd_use_events(dev);
	if (err) {
		mlx4_err(dev, "Failed to switch to event-driven "
			 "firmware commands, aborting.\n");
		goto err_eq_table_free;
	}

	err = mlx4_NOP(dev);
	if (err) {
		if (dev->flags & MLX4_FLAG_MSI_X) {
			mlx4_warn(dev, "NOP command failed to generate MSI-X "
				  "interrupt IRQ %d).\n",
				  priv->eq_table.eq[dev->caps.num_comp_vectors].irq);
			mlx4_warn(dev, "Trying again without MSI-X.\n");
		} else {
			mlx4_err(dev, "NOP command failed to generate interrupt "
				 "(IRQ %d), aborting.\n",
				 priv->eq_table.eq[dev->caps.num_comp_vectors].irq);
			mlx4_err(dev, "BIOS or ACPI interrupt routing problem?\n");
		}

		goto err_cmd_poll;
	}

	mlx4_dbg(dev, "NOP command IRQ test passed\n");

	err = mlx4_init_cq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "completion queue table, aborting.\n");
		goto err_cmd_poll;
	}

#if 0
	err = mlx4_init_srq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "shared receive queue table, aborting.\n");
		goto err_cq_table_free;
	}
#endif

	err = mlx4_init_qp_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "queue pair table, aborting.\n");
		goto err_srq_table_free;
	}

#if 0
	err = mlx4_init_mcg_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "multicast group table, aborting.\n");
		goto err_qp_table_free;
	}
#endif

	err = mlx4_init_counters_table(dev);
	if (err && err != -ENOENT) {
		mlx4_err(dev, "Failed to initialize counters table, aborting.\n");
		goto err_counters_table_free;
	}

	for (port = 1; port <= dev->caps.num_ports; port++) {
		enum mlx4_port_type port_type = 0;
//		mlx4_SENSE_PORT(dev, port, &port_type);
//		if (port_type)
//			dev->caps.port_type[port] = port_type;
		ib_port_default_caps = 0;
		err = mlx4_get_port_ib_caps(dev, port, &ib_port_default_caps);
		if (err)
			mlx4_warn(dev, "failed to get port %d default "
				  "ib capabilities (%d). Continuing with "
				  "caps = 0\n", port, err);
		dev->caps.ib_port_def_cap[port] = ib_port_default_caps;

		err = mlx4_check_ext_port_caps(dev, port);
		if (err)
			mlx4_warn(dev, "failed to get port %d extended "
				  "port capabilities support info (%d)."
				  " Assuming not supported\n", port, err);

		err = mlx4_SET_PORT(dev, port);
		if (err) {
			mlx4_err(dev, "Failed to set port %d, aborting\n",
				port);
			goto err_mcg_table_free;
		}
	}
	mlx4_set_port_mask(dev);

	//pr_debug("%s exit\n",__func__);

	return 0;

err_mcg_table_free:
//	mlx4_cleanup_mcg_table(dev);

err_counters_table_free:
	mlx4_cleanup_counters_table(dev);

err_qp_table_free:
	mlx4_cleanup_qp_table(dev);

err_srq_table_free:
//	mlx4_cleanup_srq_table(dev);

err_cq_table_free:
	mlx4_cleanup_cq_table(dev);

err_cmd_poll:
	mlx4_cmd_use_polling(dev);

err_eq_table_free:
	mlx4_cleanup_eq_table(dev);

err_mr_table_free:
	mlx4_cleanup_mr_table(dev);

err_xrcd_table_free:
//	mlx4_cleanup_xrcd_table(dev);

err_pd_table_free:
	mlx4_cleanup_pd_table(dev);

err_kar_unmap:
	iounmap(priv->kar);

err_uar_free:
	mlx4_uar_free(dev, &priv->driver_uar);

err_uar_table_free:
	mlx4_cleanup_uar_table(dev);
	return err;
}

static void mlx4_enable_msi_x(struct mlx4_dev *dev)
{
	pr_info("%s(): TODO\n");
}

static int mlx4_init_port_info(struct mlx4_dev *dev, int port)
{
	struct mlx4_port_info *info = &mlx4_priv(dev)->port[port];
	int err = 0;

	info->dev = dev;
	info->port = port;
	mlx4_init_mac_table(dev, &info->mac_table);
	mlx4_init_vlan_table(dev, &info->vlan_table);
	info->base_qpn = dev->caps.reserved_qps_base[MLX4_QP_REGION_ETH_ADDR] +
			(port - 1) * (1 << log_num_mac);

#if 0
	sprintf(info->dev_name, "mlx4_port%d", port);
	info->port_attr.attr.name = info->dev_name;
	info->port_attr.attr.mode = S_IRUGO | S_IWUSR;
	info->port_attr.show      = show_port_type;
	info->port_attr.store     = set_port_type;
	sysfs_attr_init(&info->port_attr.attr);

	err = device_create_file(&dev->pdev->dev, &info->port_attr);
	if (err) {
		mlx4_err(dev, "Failed to create file for port %d\n", port);
		info->port = -1;
	}
#endif
	return err;
}

#define MLX4_OWNER_BASE	0x8069c
#define MLX4_OWNER_SIZE	4

static int mlx4_get_ownership(struct mlx4_dev *dev)
{
	void __iomem *owner;
	u32 ret;

	if (pci_channel_offline(dev->pdev))
		return -EIO;

	owner = ioremap(pci_resource_start(dev->pdev, 0) + MLX4_OWNER_BASE,
			MLX4_OWNER_SIZE);
	if (!owner) {
		mlx4_err(dev, "Failed to obtain ownership bit\n");
		return -ENOMEM;
	}

	ret = readl(owner);
	iounmap(owner);
	return (int) !!ret;
}

static int mlx4_init_steering(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int num_entries = dev->caps.num_ports;
	int i, j;

	priv->steer = kzalloc(sizeof(struct mlx4_steer) * num_entries, GFP_KERNEL);
	if (!priv->steer)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		for (j = 0; j < MLX4_NUM_STEERS; j++) {
			INIT_LIST_HEAD(&priv->steer[i].promisc_qps[j]);
			INIT_LIST_HEAD(&priv->steer[i].steer_entries[j]);
		}
	return 0;
}

int mlx4_multi_func_init(struct mlx4_dev *dev)
{
	panic("Not supported. Need to port.\n");
	return 0;
}

/*
 * Failure is simply not an option for Lego.
 * Panic if anything went wrong.
 */
static int __mlx4_init_one(struct pci_dev *pdev, int pci_dev_data)
{
	struct mlx4_priv *priv;
	struct mlx4_dev *dev;
	int err;
	int port;
	u16 old_cmd, cmd;

	pr_debug("Initializing %s\n", pci_name(pdev));

	err = pci_enable_device(pdev);
	if (err) {
		pr_err("Fail to enable PCI device\n");
		goto err;
	}

	/*
	 * Check for BARs.
	 */
	if (!(pci_dev_data & MLX4_PCI_DEV_IS_VF) &&
	    !(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		pr_info("pci %s: Missing DCS, aborting."
			"(driver_data: 0x%x, pci_resource_flags(pdev, 0):0x%lx)\n",
			pci_name(pdev),
			pci_dev_data, pci_resource_flags(pdev, 0));
		err = -ENODEV;
		goto err;
	}

	if (!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
		pr_info("pci %s: Missing UAR, aborting.\n",
			pci_name(pdev));
		err = -ENODEV;
		goto err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		pr_info("pci %s: Couldn't get PCI resources, aborting\n",
			pci_name(pdev));
		goto err;
	}

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		pr_info("pci %s: Warning: couldn't set 64-bit PCI DMA mask.\n",
			pci_name(pdev));
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			pr_info("pci %s: Can't set PCI DMA mask, aborting.\n",
				pci_name(pdev));
			goto err;
		}
	}
	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		pr_info("pci %s: Warning: couldn't set 64-bit "
			 "consistent PCI DMA mask.\n", pci_name(pdev));
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			pr_info("pci %s: Can't set consistent PCI DMA mask, "
				"aborting.\n", pci_name(pdev));
			goto err;
		}
	}

	/* Allow large DMA segments, up to the firmware limit of 1 GB */
	dma_set_max_seg_size(&pdev->dev, 1024 * 1024 * 1024);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		err = -ENOMEM;
		goto err;
	}

	dev       = &priv->dev;
	dev->pdev = pdev;
	INIT_LIST_HEAD(&priv->ctx_list);
	spin_lock_init(&priv->ctx_lock);

	mutex_init(&priv->port_mutex);

	INIT_LIST_HEAD(&priv->pgdir_list);
	mutex_init(&priv->pgdir_mutex);

	INIT_LIST_HEAD(&priv->bf_list);
	mutex_init(&priv->bf_mutex);

	dev->rev_id = pdev->revision;
	/* Detect if this device is a virtual function */
	if (pci_dev_data & MLX4_PCI_DEV_IS_VF) {
		pr_warn("WARNING: Detected virtual function - running in slave mode\n");
		dev->flags |= MLX4_FLAG_SLAVE;
	} else {
		/*
		 * We reset the device and enable SRIOV only for physical
		 * devices.  Try to claim ownership on the device;
		 * if already taken, skip -- do not allow multiple PFs
		 */
		err = mlx4_get_ownership(dev);
		if (err) {
			if (err < 0) {
				pr_warn("Some internal error?\n");
				goto err;
			} else {
				pr_warn("Multiple PFs not yet supported."
					  " Skipping PF.\n");
				err = -EINVAL;
				goto err;
			}
		}

		/*
		 * Now reset the HCA before we touch the PCI capabilities or
		 * attempt a firmware command, since a boot ROM may have left
		 * the HCA in an undefined state.
		 */
		err = mlx4_reset(dev);
		if (err) {
			mlx4_err(dev, "Failed to reset HCA, aborting.\n");
			goto err;
		}
	}

	/*
	 * HACK!!!
	 *
	 * So.. in our current wuklab testbed, we dev->flags=0, which
	 * means it is neither slave nor master. If, you happen to have
	 * something else, please port or report.
	 */

slave_start:
	err = mlx4_cmd_init(dev);
	if (err) {
		pr_err("Failed to init command interface, aborting.\n");
		goto err;
	}

	/* In slave functions, the communication channel must be initialized
	 * before posting commands. Also, init num_slaves before calling
	 * mlx4_init_hca */
	if (mlx4_is_mfunc(dev))
		panic("Not supported now. Need more port.\n");

	err = mlx4_init_hca(dev);
	if (err) {
		if (err == -EACCES) {
			/* Not primary Physical function
			 * Running in slave mode */
			mlx4_cmd_cleanup(dev);
			dev->flags |= MLX4_FLAG_SLAVE;
			dev->flags &= ~MLX4_FLAG_MASTER;
			goto slave_start;
		} else
			goto err;
	}

	/* In master functions, the communication channel must be initialized
	 * after obtaining its address from fw */
	if (mlx4_is_master(dev)) {
		err = mlx4_multi_func_init(dev);
		if (err) {
			pr_err("Failed to init master mfunc"
				 "interface, aborting.\n");
			goto err;
		}
	}

	err = mlx4_alloc_eq_table(dev);
	if (err)
		goto err;

	priv->msix_ctl.pool_bm = 0;
	mutex_init(&priv->msix_ctl.pool_lock);

	mlx4_enable_msi_x(dev);
	if (!mlx4_is_slave(dev)) {
		err = mlx4_init_steering(dev);
		if (err)
			goto err;
	}

	err = mlx4_setup_hca(dev);
	if (err)
		goto err;

	for (port = 1; port <= dev->caps.num_ports; port++) {
		err = mlx4_init_port_info(dev, port);
		if (err)
			goto err;
	}

	err = mlx4_register_device(dev);
	if (err)
		goto err;

#if 0
	mlx4_sense_init(dev);
	mlx4_start_sense(dev);

	priv->pci_dev_data = pci_dev_data;
	pci_set_drvdata(pdev, dev);
#endif

	return 0;

	panic("Need more on enable pci device\n");
	mlx4_ib_init();

err:
	panic("Fail to register mlx4 %s device!\n", pci_name(pdev));
	return -ENODEV;
}

static int mlx4_init_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	return __mlx4_init_one(pdev, id->driver_data);
}

void mlx4_remove_one(struct pci_dev *pdev) { }

static DEFINE_PCI_DEVICE_TABLE(mlx4_pci_table) = {
	/* MT25408 "Hermon" SDR */
	{ PCI_VDEVICE(MELLANOX, 0x6340), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25408 "Hermon" DDR */
	{ PCI_VDEVICE(MELLANOX, 0x634a), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25408 "Hermon" QDR */
	{ PCI_VDEVICE(MELLANOX, 0x6354), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25408 "Hermon" DDR PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x6732), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25408 "Hermon" QDR PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x673c), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25408 "Hermon" EN 10GigE */
	{ PCI_VDEVICE(MELLANOX, 0x6368), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25408 "Hermon" EN 10GigE PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x6750), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25458 ConnectX EN 10GBASE-T 10GigE */
	{ PCI_VDEVICE(MELLANOX, 0x6372), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	{ PCI_VDEVICE(MELLANOX, 0x675a), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT26468 ConnectX EN 10GigE PCIe gen2*/
	{ PCI_VDEVICE(MELLANOX, 0x6764), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT26438 ConnectX EN 40GigE PCIe gen2 5GT/s */
	{ PCI_VDEVICE(MELLANOX, 0x6746), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT26478 ConnectX2 40GigE PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x676e), MLX4_PCI_DEV_FORCE_SENSE_PORT },
	/* MT25400 Family [ConnectX-2 Virtual Function] */
	{ PCI_VDEVICE(MELLANOX, 0x1002), MLX4_PCI_DEV_IS_VF },
	/* MT27500 Family [ConnectX-3] */
	{ PCI_VDEVICE(MELLANOX, 0x1003), 0 },
	/* MT27500 Family [ConnectX-3 Virtual Function] */
	{ PCI_VDEVICE(MELLANOX, 0x1004), MLX4_PCI_DEV_IS_VF },
	{ PCI_VDEVICE(MELLANOX, 0x1005), 0 }, /* MT27510 Family */
	{ PCI_VDEVICE(MELLANOX, 0x1006), 0 }, /* MT27511 Family */
	{ PCI_VDEVICE(MELLANOX, 0x1007), 0 }, /* MT27520 Family */
	{ PCI_VDEVICE(MELLANOX, 0x1008), 0 }, /* MT27521 Family */
	{ PCI_VDEVICE(MELLANOX, 0x1009), 0 }, /* MT27530 Family */
	{ PCI_VDEVICE(MELLANOX, 0x100a), 0 }, /* MT27531 Family */
	{ PCI_VDEVICE(MELLANOX, 0x100b), 0 }, /* MT27540 Family */
	{ PCI_VDEVICE(MELLANOX, 0x100c), 0 }, /* MT27541 Family */
	{ PCI_VDEVICE(MELLANOX, 0x100d), 0 }, /* MT27550 Family */
	{ PCI_VDEVICE(MELLANOX, 0x100e), 0 }, /* MT27551 Family */
	{ PCI_VDEVICE(MELLANOX, 0x100f), 0 }, /* MT27560 Family */
	{ PCI_VDEVICE(MELLANOX, 0x1010), 0 }, /* MT27561 Family */
	{ 0, }
};

static struct pci_driver mlx4_driver = {
	.name		= "mlx4_core",
	.id_table	= mlx4_pci_table,
	.probe		= mlx4_init_one,
	.remove		= mlx4_remove_one,
};

int __init mlx4_init(void)
{
	int ret;

	/*
	 * Register our driver, the solo purpose is to
	 * let PCI subsystem try to find a device and call back
	 * our mlx4_init_one().
	 */
	ret = pci_register_driver(&mlx4_driver);
	if (ret < 0)
		panic("Fail to register mlx4 PCI driver");
	return 0;
}
