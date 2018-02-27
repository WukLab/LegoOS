/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Processor manager internal header file */

#ifndef _PROCESSOR_COMPONENT_PROCESSOR_H_
#define _PROCESSOR_COMPONENT_PROCESSOR_H_

#include <lego/compiler.h>

void __init pcache_early_init(void);
void __init pcache_post_init(void);

#endif /* _PROCESSOR_COMPONENT_PROCESSOR_H_ */
