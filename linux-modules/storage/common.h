/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/*
 * Rules about our message opcodes:
 *
 * 1) Prefix:
 *	P2M: processor -> memory
 *	M2P: memory -> processor
 *	M2S: memory -> storage
 *	S2M: storage -> memory
 *
 * 2) System calls related:
 *	Follow the original SYSCALL number
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define M2S_BASE	((__u32)0x00100000)
#define M2S_READ	((__u32)(M2S_BASE)+1)
#define M2S_WRITE	((__u32)(M2S_BASE)+2)
#define STOREAGE_NODE	1
#define MEM_NODE	0

struct common_header {
	__u32	opcode;		/* see above */
	__u32	src_nid;	/* source nid */
	__u32	length;		/* of the whole message */
};

/* fit module */
extern int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int if_use_ret_phys_addr);
extern int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);
extern int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int if_use_ret_phys_addr);

static inline struct common_header *to_common_header(void *msg)
{
	return (struct common_header *)(msg);
}

static inline void *to_payload(void *msg)
{
	return (void *)(msg + sizeof(struct common_header));
}

static inline int net_send_reply_timeout(u32 node, u32 opcode,
			   void *payload, u32 len_payload,
			   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys,
			   u32 timeout)
{
	int ret;
	u32 len_msg;
	void *msg, *payload_msg;
	struct common_header *hdr;

	BUG_ON(!payload || !retbuf);

	/* compose message */
	len_msg = len_payload + sizeof(*hdr);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		WARN(1, "OOM");
		return -ENOMEM;
	}

	hdr = to_common_header(msg);
	hdr->opcode = opcode;
	hdr->src_nid = MEM_NODE;
	hdr->length = sizeof(*hdr) + len_payload;

	payload_msg = to_payload(msg);
	memcpy(payload_msg, payload, len_payload);

	/* Synchronously send it out */
	ret = ibapi_send_reply_imm(node, msg, len_msg, retbuf,
				   max_len_retbuf, retbuf_is_phys);

	kfree(msg);
	return ret;
}

#define DEF_MAX_TIMEOUT	100

static inline int net_send_reply(u32 node, u32 opcode,
		   void *payload, u32 len_payload,
		   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys)
{
	return net_send_reply_timeout(node, opcode,
				payload, len_payload,
				retbuf, max_len_retbuf, retbuf_is_phys,
				DEF_MAX_TIMEOUT);
}


#define MAX_ARG_STRLEN		(PAGE_SIZE * 32)
#define MAX_ARG_STRINGS		0x7FFFFFFF

#define MAX_FILENAME_LENGTH	256


/* M2S_READ */
struct m2s_read {
	__u32	pid;
	char    filename[MAX_FILENAME_LENGTH];
};

/* M2S_WRITE */
struct m2s_write {
	__u32	pid;
	char    filename[MAX_FILENAME_LENGTH];
};
