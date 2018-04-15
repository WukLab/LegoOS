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
#include <memory/replica_types.h>

/*
 * BIG FAT NOTE:
 * Storage recevier only expect the opcode at top.
 * No struct common_header should be used here.
 *
 * It is not consistent with the rest of system,
 * should be changed!
 */

/* M2S_READ */
/* M2S_WRITE */
struct m2s_read_write_payload {
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	int	flags;
	size_t	len;
	loff_t	offset;
};

struct m2s_lseek_struct {
	char filename[MAX_FILENAME_LENGTH];
};

/* M2S_REPLICA_FLUSH */
struct m2s_replica_flush_msg {
	unsigned int		opcode;
	unsigned int		nr_log;

	/* variable length buffer */
	char			log[0];
};

/* M2S_REPLICA_VMA */
struct m2s_replica_vma_msg {
	unsigned int		opcode;
	struct replica_vma_log	log;
};

#endif /* _LEGO_RPC_STRUCT_M2S_H_ */
