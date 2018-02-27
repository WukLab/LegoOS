/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * x86 FPU signal frame handling methods:
 */

#ifndef _ASM_X86_FPU_SIGNAL_H_
#define _ASM_X86_FPU_SIGNAL_H_

#ifdef CONFIG_X86_64
# include <asm/sigcontext.h>
# include <asm/user32.h>
# include <lego/compat.h>
struct ksignal;
int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
			compat_sigset_t *set, struct pt_regs *regs);
int ia32_setup_frame(int sig, struct ksignal *ksig,
		     compat_sigset_t *set, struct pt_regs *regs);
#else
#error "BUG"
# define user_i387_ia32_struct	user_i387_struct
# define user32_fxsr_struct	user_fxsr_struct
# define ia32_setup_frame	__setup_frame
# define ia32_setup_rt_frame	__setup_rt_frame
#endif


extern void convert_from_fxsr(struct user_i387_ia32_struct *env,
			      struct task_struct *tsk);
extern void convert_to_fxsr(struct task_struct *tsk,
			    const struct user_i387_ia32_struct *env);

unsigned long
fpu__alloc_mathframe(unsigned long sp, int ia32_frame,
		     unsigned long *buf_fx, unsigned long *size);

extern void fpu__init_prepare_fx_sw_frame(void);


#endif /* _ASM_X86_FPU_SIGNAL_H_ */
