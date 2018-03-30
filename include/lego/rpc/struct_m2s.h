/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RPC_STRUCT_M2S_H_
#define _LEGO_RPC_STRUCT_M2S_H_

#include <lego/rpc/struct_common.h>

/* M2S_READ */
/* M2S_WRITE */
struct m2s_read_write_payload{
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	int	flags;
	size_t	len;
	loff_t	offset;
};

#endif /* _LEGO_RPC_STRUCT_M2S_H_ */
