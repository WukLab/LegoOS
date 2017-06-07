/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include "processor.h"

/**
 * processor_component_init
 *
 * Initiliaze all processor component contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_component_init(void)
{
	processor_cache_init();
}
