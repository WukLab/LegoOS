/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_UTSNAME_H_
#define _LEGO_UTSNAME_H_

/*
 * Defines for what uname() should return 
 */

#define UTS_SYSNAME	"LegoOS"

#define UTS_NODENAME	CONFIG_DEFAULT_HOSTNAME /* set by sethostname() */

#define UTS_DOMAINNAME	"(none)"	/* set by setdomainname() */

#define UTS_LEN 64

struct utsname {
	char sysname[UTS_LEN + 1];
	char nodename[UTS_LEN + 1];
	char release[UTS_LEN + 1];
	char version[UTS_LEN + 1];
	char machine[UTS_LEN + 1];
	char domainname[UTS_LEN + 1];
};

extern struct utsname utsname;

#endif /* _LEGO_UTSNAME_H_ */
