#ifndef _LEGO_BOOT_STRING_H_
#define _LEGO_BOOT_STRING_H_

/*
 * Access builtin version by default. If one needs to use optimized version,
 * do "undef memcpy" in .c file and link against right string.c
 */
#define memcpy(d,s,l) __builtin_memcpy(d,s,l)
#define memset(d,c,l) __builtin_memset(d,c,l)
#define memcmp	__builtin_memcmp

#endif /* _LEGO_BOOT_STRING_H_ */
