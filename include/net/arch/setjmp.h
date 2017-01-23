#ifndef LEGO_INC_SETJMP_H
#define LEGO_INC_SETJMP_H

#include <lego/types.h>

#define LEGO_LONGJMP_GCCATTR	regparm(2)

struct lego_jmp_buf {
    u64 jb_rip;
    u64 jb_rsp;
    u64 jb_rbp;
    u64 jb_rbx;
    u64 jb_rsi;
    u64 jb_rdi;
    u64 jb_r15;
    u64 jb_r14;
    u64 jb_r13;
    u64 jb_r12;
    u64 jb_r11;
    u64 jb_r10;
    u64 jb_r9;
    u64 jb_r8;
};

int  lego_setjmp(volatile struct lego_jmp_buf *buf);
void lego_longjmp(volatile struct lego_jmp_buf *buf, int val)
	__attribute__((__noreturn__, LEGO_LONGJMP_GCCATTR));

#endif
