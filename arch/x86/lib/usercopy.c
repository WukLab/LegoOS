/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/uaccess.h>
#include <lego/sched.h>
#include <lego/string.h>

/*
 * Try to copy last bytes and clear the rest if needed.
 * Since protection fault in copy_from/to_user is not a normal situation,
 * it is not necessary to optimize tail handling.
 */
__visible unsigned long
copy_user_handle_tail(char *to, char *from, unsigned len)
{
	for (; len; --len, to++) {
		char c;

		if (get_user(c, from++))
			break;
		if (put_user(c, to))
			break;
	}

	/* If the destination is a kernel buffer, we always clear the end */
	if (!__addr_ok(to))
		memset(to, 0, len);
	return len;
}
