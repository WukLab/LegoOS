/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/tracepoint.h>

#define __def_pteflag_names					\
	{1UL << _PAGE_BIT_PRESENT,	"present"	},	\
	{1UL << _PAGE_BIT_RW,		"writable"	},	\
	{1UL << _PAGE_BIT_USER,		"user"		},	\
	{1UL << _PAGE_BIT_PWT,		"wr_through"	},	\
	{1UL << _PAGE_BIT_PCD,		"$_disable"	},	\
	{1UL << _PAGE_BIT_ACCESSED,	"accessed"	},	\
	{1UL << _PAGE_BIT_DIRTY,	"dirty"		},	\
	{1UL << _PAGE_BIT_PSE,		"large"		},	\
	{1UL << _PAGE_BIT_PAT,		"pat"		},	\
	{1UL << _PAGE_BIT_GLOBAL,	"global"	},	\
	{1UL << _PAGE_BIT_SOFTW1,	"softw1"	},	\
	{1UL << _PAGE_BIT_SOFTW2,	"softw2_zfill"	},	\
	{1UL << _PAGE_BIT_SOFTW3,	"softw3_zfill_locked"	},	\
	{1UL << _PAGE_BIT_PAT_LARGE,	"pat_large"	},	\
	{1UL << _PAGE_BIT_SOFTW4,	"softw4"	},	\
	{1UL << _PAGE_BIT_PKEY_BIT0,	"pkey0"		},	\
	{1UL << _PAGE_BIT_PKEY_BIT1,	"pkey1"		},	\
	{1UL << _PAGE_BIT_PKEY_BIT2,	"pkey2"		},	\
	{1UL << _PAGE_BIT_PKEY_BIT3,	"pkey3"		},	\
	{1UL << _PAGE_BIT_NX,		"nx"		}

const struct trace_print_flags pteflag_names[] = {
	__def_pteflag_names,
	{0, NULL}
};

void dump_pte(pte_t *ptep, const char *reason)
{
	pr_debug("pte:%p (%#lx) pfn:%#lx flags:(%pGe)\n",
		ptep, (unsigned long)(ptep->pte), pte_pfn(*ptep), ptep);
	if (reason)
		pr_debug("pte dumped because: %s\n", reason);
}
