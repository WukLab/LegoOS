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
#define ___GFP_HIGH		0x20u
#define ___GFP_IO		0x40u
#define ___GFP_COLD		0x100u
#define ___GFP_NOWARN		0x200u
#define ___GFP_REPEAT		0x400u
#define ___GFP_NOFAIL		0x800u
#define ___GFP_ZERO		0x8000u
#define ___GFP_THISNODE		0x40000u
#define ___GFP_ATOMIC		0x80000u

/*
 * Physical address zone modifiers
 */
#define __GFP_DMA	((gfp_t)___GFP_DMA)
#define __GFP_DMA32	((gfp_t)___GFP_DMA32)
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_DMA32)

/*
 * Page mobility and placement hints
 *
 * __GFP_THISNODE forces the allocation to be satisified from the requested
 *   node with no fallbacks or placement policy enforcements.
 */
#define __GFP_THISNODE	((gfp_t)___GFP_THISNODE)

/*
 * Watermark modifiers -- controls access to emergency reserves
 *
 * __GFP_ATOMIC indicates that the caller cannot reclaim or sleep and is
 *   high priority. Users are typically interrupt handlers. This may be
 *   used in conjunction with __GFP_HIGH
 *
 * __GFP_HIGH indicates that the caller is high-priority and that granting
 *   the request is necessary before the system can make forward progress.
 *   For example, creating an IO context to clean pages.
 *
 */
#define __GFP_ATOMIC	((gfp_t)___GFP_ATOMIC)
#define __GFP_HIGH	((gfp_t)___GFP_HIGH)

/*
 * Reclaim modifiers
 *
 * __GFP_IO can start physical IO.
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 *   _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 *   cannot handle allocation failures. New users should be evaluated carefully
 *   (and the flag should be used only when there is no reasonable failure
 *   policy) but it is definitely preferable to use the flag rather than
 *   opencode endless loop around allocator.
 *
 */
#define __GFP_IO	((gfp_t)___GFP_IO)
#define __GFP_REPEAT	((gfp_t)___GFP_REPEAT)
#define __GFP_NOFAIL	((gfp_t)___GFP_NOFAIL)

/*
 * Action modifiers
 *
 * __GFP_COLD indicates that the caller does not expect to be used in the near
 *   future. Where possible, a cache-cold page will be returned.
 *
 * __GFP_NOWARN suppresses allocation failure reports.
 *
 * __GFP_ZERO returns a zeroed page on success.
 */
#define __GFP_COLD	((gfp_t)___GFP_COLD)
#define __GFP_NOWARN	((gfp_t)___GFP_NOWARN)
#define __GFP_ZERO	((gfp_t)___GFP_ZERO)

#define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC)
#define GFP_KERNEL	(__GFP_IO)
#define GFP_DMA		__GFP_DMA
#define GFP_DMA32	__GFP_DMA32

static inline int gfp_zone(gfp_t flags)
{
	int z = flags & GFP_ZONEMASK;
	return z;
}

#endif /* _LEGO_GFP_H_ */
