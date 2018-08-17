/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <lego/errno.h>
#include <lego/mlx4/cmd.h>

#include "mlx4.h"

int mlx4_SENSE_PORT(struct mlx4_dev *dev, int port,
		    enum mlx4_port_type *type)
{
	u64 out_param;
	int err = 0;

	err = mlx4_cmd_imm(dev, 0, &out_param, port, 0,
			   MLX4_CMD_SENSE_PORT, MLX4_CMD_TIME_CLASS_B);
	if (err) {
		mlx4_err(dev, "Sense command failed for port: %d\n", port);
		return err;
	}

	if (out_param > 2) {
		mlx4_err(dev, "Sense returned illegal value: 0x%llx\n", out_param);
		return -EINVAL;
	}

	*type = out_param;
	return 0;
}
