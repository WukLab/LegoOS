/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_GFP_H_
#define _LEGO_GFP_H_

#define ___GFP_DMA		0x01u
#define ___GFP_DMA32		0x04u
#define ___GFP_IO		0x40u
#define ___GFP_NOFAIL		0x800u
#define ___GFP_ATOMIC		0x80000u

#define __GFP_DMA	((gfp_t)___GFP_DMA)
#define __GFP_DMA32	((gfp_t)___GFP_DMA32)
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_DMA32|)

#define __GFP_ATOMIC	((gfp_t)___GFP_ATOMIC)

#define __GFP_IO	((gfp_t)___GFP_IO)
#define __GFP_NOFAIL	((gfp_t)___GFP_NOFAIL)

/*
 *
 */
#define GFP_KERNEL	(__GFP_IO)

#endif /* _LEGO_GFP_H_ */
