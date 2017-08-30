/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CHECKPOINT_H_
#define _LEGO_CHECKPOINT_H_

#include <lego/types.h>

struct ss_file {

};

struct ss_files {

};

struct ss_task {
	pid_t		pid;
	unsigned long	user_ip;
	unsigned long	user_sp;
};

struct snapshot {
	
};

#endif /* _LEGO_CHECKPOINT_H_ */
