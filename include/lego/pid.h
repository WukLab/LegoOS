/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PID_H_
#define _LEGO_PID_H_

pid_t alloc_pid(void);
void free_pid(pid_t pid);

#endif /* _LEGO_PID_H_ */
