/*
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
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

#include <lego/errno.h>
//#include <lego/io-mapping.h>

#include <asm/page.h>

#include "mlx4.h"
#include "icm.h"

enum {
	MLX4_NUM_RESERVED_UARS = 8
};

int mlx4_pd_alloc(struct mlx4_dev *dev, u32 *pdn)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	*pdn = mlx4_bitmap_alloc(&priv->pd_bitmap);
	if (*pdn == -1)
		return -ENOMEM;

	return 0;
}

void mlx4_pd_free(struct mlx4_dev *dev, u32 pdn)
{
	mlx4_bitmap_free(&mlx4_priv(dev)->pd_bitmap, pdn);
}

int __mlx4_xrcd_alloc(struct mlx4_dev *dev, u32 *xrcdn)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	*xrcdn = mlx4_bitmap_alloc(&priv->xrcd_bitmap);
	if (*xrcdn == -1)
		return -ENOMEM;

	return 0;
}

int mlx4_xrcd_alloc(struct mlx4_dev *dev, u32 *xrcdn)
{
	u64 out_param;
	int err;

	if (mlx4_is_mfunc(dev)) {
		err = mlx4_cmd_imm(dev, 0, &out_param,
				   RES_XRCD, RES_OP_RESERVE,
				   MLX4_CMD_ALLOC_RES,
				   MLX4_CMD_TIME_CLASS_A);
		if (err)
			return err;

		*xrcdn = get_param_l(&out_param);
		return 0;
	}
	return __mlx4_xrcd_alloc(dev, xrcdn);
}

void __mlx4_xrcd_free(struct mlx4_dev *dev, u32 xrcdn)
{
	mlx4_bitmap_free(&mlx4_priv(dev)->xrcd_bitmap, xrcdn);
}

void mlx4_xrcd_free(struct mlx4_dev *dev, u32 xrcdn)
{
	u64 in_param = 0;
	int err;

	if (mlx4_is_mfunc(dev)) {
		set_param_l(&in_param, xrcdn);
		err = mlx4_cmd(dev, in_param, RES_XRCD,
			       RES_OP_RESERVE, MLX4_CMD_FREE_RES,
			       MLX4_CMD_TIME_CLASS_A);
		if (err)
			mlx4_warn(dev, "Failed to release xrcdn %d\n", xrcdn);
	} else
		__mlx4_xrcd_free(dev, xrcdn);
}

int mlx4_init_pd_table(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	return mlx4_bitmap_init(&priv->pd_bitmap, dev->caps.num_pds,
				(1 << NOT_MASKED_PD_BITS) - 1,
				 dev->caps.reserved_pds, 0);
}

void mlx4_cleanup_pd_table(struct mlx4_dev *dev)
{
	mlx4_bitmap_cleanup(&mlx4_priv(dev)->pd_bitmap);
}

int mlx4_init_xrcd_table(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	return mlx4_bitmap_init(&priv->xrcd_bitmap, (1 << 16),
				(1 << 16) - 1, dev->caps.reserved_xrcds + 1, 0);
}

void mlx4_cleanup_xrcd_table(struct mlx4_dev *dev)
{
	mlx4_bitmap_cleanup(&mlx4_priv(dev)->xrcd_bitmap);
}

int mlx4_uar_alloc(struct mlx4_dev *dev, struct mlx4_uar *uar)
{
	int offset;

	uar->index = mlx4_bitmap_alloc(&mlx4_priv(dev)->uar_table.bitmap);
	if (uar->index == -1)
		return -ENOMEM;

	if (mlx4_is_slave(dev))
		offset = uar->index % ((int) pci_resource_len(dev->pdev, 2) /
				       dev->caps.uar_page_size);
	else
		offset = uar->index;
	uar->pfn = (pci_resource_start(dev->pdev, 2) >> PAGE_SHIFT) + offset;
	uar->map = NULL;
	return 0;
}

void mlx4_uar_free(struct mlx4_dev *dev, struct mlx4_uar *uar)
{
	mlx4_bitmap_free(&mlx4_priv(dev)->uar_table.bitmap, uar->index);
}

int mlx4_init_uar_table(struct mlx4_dev *dev)
{
	if (dev->caps.num_uars <= 128) {
		mlx4_err(dev, "Only %d UAR pages (need more than 128)\n",
			 dev->caps.num_uars);
		mlx4_err(dev, "Increase firmware log2_uar_bar_megabytes?\n");
		return -ENODEV;
	}

	return mlx4_bitmap_init(&mlx4_priv(dev)->uar_table.bitmap,
				dev->caps.num_uars, dev->caps.num_uars - 1,
				max(128, dev->caps.reserved_uars), 0);
}

void mlx4_cleanup_uar_table(struct mlx4_dev *dev)
{
	mlx4_bitmap_cleanup(&mlx4_priv(dev)->uar_table.bitmap);
}
