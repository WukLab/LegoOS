/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CHECKSUM_H_
#define _LEGO_CHECKSUM_H_

#include <asm/checksum.h>
#include <lego/types.h>
#include <lego/compiler.h>

#ifndef HAVE_ARCH_CSUM_ADD
static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	u32 res = (__force u32)csum;
	res += (__force u32)addend;
	return (__force __wsum)(res + (res < (__force u32)addend));
}
#endif

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	u16 res = (__force u16)csum;

	res += (__force u16)addend;
	return (__force __sum16)(res + (res < (__force u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

#endif /* _LEGO_CHECKSUM_H_ */
