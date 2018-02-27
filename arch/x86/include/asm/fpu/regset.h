/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * FPU regset handling methods:
 */

#ifndef _ASM_X86_FPU_REGSET_H_
#define _ASM_X86_FPU_REGSET_H_

#include <lego/regset.h>

extern user_regset_active_fn regset_fpregs_active, regset_xregset_fpregs_active;
extern user_regset_get_fn fpregs_get, xfpregs_get, fpregs_soft_get,
				xstateregs_get;
extern user_regset_set_fn fpregs_set, xfpregs_set, fpregs_soft_set,
				 xstateregs_set;

/*
 * xstateregs_active == regset_fpregs_active. Please refer to the comment
 * at the definition of regset_fpregs_active.
 */
#define xstateregs_active	regset_fpregs_active

#endif /* _ASM_X86_FPU_REGSET_H_ */
