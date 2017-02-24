/*
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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

#include <lego/errno.h>
#include <lego/pci.h>
#include <lego/delay.h>
#include <lego/slab.h>
#include <lego/jiffies.h>

#include "mlx4.h"

int mlx4_reset(struct mlx4_dev *dev)
{
	void __iomem *reset;
	u32 *hca_header = NULL;
	int pcie_cap;
	u16 devctl;
	u16 linkctl;
	u16 vendor;
	unsigned long end;
	u32 sem;
	int i;
	int err = 0;
	u32 pci_read_val;

#define MLX4_RESET_BASE		0xf0000
#define MLX4_RESET_SIZE		  0x400
#define MLX4_SEM_OFFSET		  0x3fc
#define MLX4_RESET_OFFSET	   0x10
#define MLX4_RESET_VALUE	swab32(1)

#define MLX4_SEM_TIMEOUT_JIFFIES	(10 * HZ)
#define MLX4_RESET_TIMEOUT_JIFFIES	(2 * HZ)

	/*
	 * Reset the chip.  This is somewhat ugly because we have to
	 * save off the PCI header before reset and then restore it
	 * after the chip reboots.  We skip config space offsets 22
	 * and 23 since those have a special meaning.
	 */

	/* Do we need to save off the full 4K PCI Express header?? */
	hca_header = kmalloc(256, GFP_KERNEL);
	if (!hca_header) {
		err = -ENOMEM;
		mlx4_err(dev, "Couldn't allocate memory to save HCA "
			  "PCI header, aborting.\n");
		goto out;
	}

//	pcie_cap = pci_pcie_cap(dev->pdev);

	for (i = 0; i < 64; ++i) {
		if (i == 22 || i == 23)
			continue;
		pci_read_val = pci_conf_read(dev->pdev, i * 4, 3);
		memcpy(hca_header + i, &pci_read_val, sizeof(u32));
	}

	reset = ioremap(pci_resource_start(dev->pdev, 0) + MLX4_RESET_BASE,
			MLX4_RESET_SIZE);
	if (!reset) {
		err = -ENOMEM;
		mlx4_err(dev, "Couldn't map HCA reset register, aborting.\n");
		goto out;
	}

	int dummy, j,k;
	/* grab HW semaphore to lock out flash updates */
	end = jiffies + MLX4_SEM_TIMEOUT_JIFFIES;
	do {
		sem = readl(reset + MLX4_SEM_OFFSET);
		if (!sem)
			break;

		//msleep(1);
		udelay(1000);
	} while (time_before(jiffies, end));

	if (sem) {
		mlx4_err(dev, "Failed to obtain HW semaphore, aborting\n");
		err = -EAGAIN;
		iounmap(reset);
		goto out;
	}

	/* actually hit reset */
	writel(MLX4_RESET_VALUE, reset + MLX4_RESET_OFFSET);
	iounmap(reset);

	/* Docs say to wait one second before accessing device */
	for (i=0;i < 10000;i++) 
		for (j=0;j < 10000;j++) 
			for (k=0;k < 10000;k++) 
				dummy=1+2;
	mdelay(1000);

	end = jiffies + MLX4_RESET_TIMEOUT_JIFFIES;
	do {
		vendor = pci_conf_read(dev->pdev, PCI_VENDOR_ID, 2); 
		if (vendor != 0xffff)
			break;

		//msleep(1);
		udelay(1000);
	} while (time_before(jiffies, end));

	if (vendor == 0xffff) {
		err = -ENODEV;
		mlx4_err(dev, "PCI device did not come back after reset, "
			  "aborting.\n");
		goto out;
	}

#if 0
	/* Now restore the PCI headers */
	if (pcie_cap) {
		devctl = hca_header[(pcie_cap + PCI_EXP_DEVCTL) / 4];
		if (pci_write_config_word(dev->pdev, pcie_cap + PCI_EXP_DEVCTL,
					   devctl)) {
			err = -ENODEV;
			mlx4_err(dev, "Couldn't restore HCA PCI Express "
				 "Device Control register, aborting.\n");
			goto out;
		}
		linkctl = hca_header[(pcie_cap + PCI_EXP_LNKCTL) / 4];
		if (pci_write_config_word(dev->pdev, pcie_cap + PCI_EXP_LNKCTL,
					   linkctl)) {
			err = -ENODEV;
			mlx4_err(dev, "Couldn't restore HCA PCI Express "
				 "Link control register, aborting.\n");
			goto out;
		}
	}
#endif

	for (i = 0; i < 16; ++i) {
		if (i * 4 == PCI_COMMAND)
			continue;

		pci_conf_write(dev->pdev, i * 4, hca_header[i], 3);
	}

	pci_conf_write(dev->pdev, PCI_COMMAND,
				   hca_header[PCI_COMMAND / 4], 3);

out:
	kfree(hca_header);

	return err;
}
