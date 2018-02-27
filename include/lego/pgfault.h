/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PGFAULT_H_
#define _LEGO_PGFAULT_H_

/*
 * Different kinds of faults, used by P's pgfault handler
 * and M's pcache handler.
 */
#define VM_FAULT_OOM		0x0001
#define VM_FAULT_SIGBUS		0x0002
#define VM_FAULT_MAJOR		0x0004
#define VM_FAULT_WRITE		0x0008	/* Special case for get_user_pages */
#define VM_FAULT_HWPOISON	0x0010	/* Hit poisoned small page */
#define VM_FAULT_SIGSEGV	0x0040
#define VM_FAULT_NOPAGE		0x0100	/* ->fault installed pte, not return page */
#define VM_FAULT_LOCKED		0x0200	/* ->fault locked the returned page */
#define VM_FAULT_RETRY		0x0400	/* ->fault blocked, must retry */

#define VM_FAULT_ERROR	(VM_FAULT_OOM | VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV | \
			 VM_FAULT_HWPOISON )

#endif /* _LEGO_PGFAULT_H_ */
