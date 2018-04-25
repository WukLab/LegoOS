#include <sys/utsname.h>
#include <math.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <linux/unistd.h>
#include <assert.h>

#include <uapi/processor/pcache.h>

#define BUG_ON(cond)	assert(!(cond))

#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE - 1))

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y)	((__typeof__(x))((y)-1))
#define round_up(x, y)		((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)	((x) & ~__round_mask(x, y))

#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))

#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define __NR_CHECKPOINT	666

static inline void die(const char * str, ...)
{
	va_list args;
	va_start(args, str);
	vfprintf(stderr, str, args);
	fputc('\n', stderr);
	exit(1);
}

/*
 * result: diff
 * x: end time
 * y: start time
 */
static inline int timeval_sub(struct timeval *result, struct timeval *x,
			  struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

static inline struct timeval
timeval_add(struct timeval *a, struct timeval *b)
{
	struct timeval result;

	result.tv_sec = a->tv_sec + b->tv_sec;
	result.tv_usec = a->tv_usec + b->tv_usec;
	if (result.tv_usec >= 1000000) {
		result.tv_sec += 1;
		result.tv_usec -= 1000000;
	}
	return result;
}

static inline pid_t gettid(void)
{
	syscall(SYS_gettid);
}

static inline void checkpoint_process(pid_t pid)
{
	long ret;

	ret = syscall(__NR_CHECKPOINT, pid);
	if (ret < 0)
		perror("checkpoint");
}

static inline int pcache_stat(struct pcache_stat *buf)
{
	int ret;

	ret = syscall(__NR_pcache_stat, buf);
	if (ret < 0) {
		memset(buf, 0, sizeof(*buf));
	}
	return ret;
}

static inline unsigned short from32to16(unsigned a) 
{
	unsigned short b = a >> 16; 
	asm("addw %w2,%w0\n\t"
	    "adcw $0,%w0\n" 
	    : "=r" (b)
	    : "0" (b), "r" (a));
	return b;
}

static inline unsigned int add32_with_carry(unsigned a, unsigned b)
{
	asm("addl %2,%0\n\t"
	    "adcl $0,%0"
	    : "=r" (a)
	    : "0" (a), "rm" (b));
	return a;
}

/*
 * Do a 64-bit checksum on an arbitrary memory area.
 * Returns a 32bit checksum.
 *
 * This isn't as time critical as it used to be because many NICs
 * do hardware checksumming these days.
 * 
 * Things tried and found to not make it faster:
 * Manual Prefetching
 * Unrolling to an 128 bytes inner loop.
 * Using interleaving with more registers to break the carry chains.
 */
static unsigned do_csum(const unsigned char *buff, unsigned len)
{
	unsigned odd, count;
	unsigned long result = 0;

	if (len == 0)
		return result; 
	odd = 1 & (unsigned long) buff;
	if (odd) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *)buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned long zero;
			unsigned count64;
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */

			/* main loop using 64byte blocks */
			zero = 0;
			count64 = count >> 3;
			while (count64) { 
				asm("addq 0*8(%[src]),%[res]\n\t"
				    "adcq 1*8(%[src]),%[res]\n\t"
				    "adcq 2*8(%[src]),%[res]\n\t"
				    "adcq 3*8(%[src]),%[res]\n\t"
				    "adcq 4*8(%[src]),%[res]\n\t"
				    "adcq 5*8(%[src]),%[res]\n\t"
				    "adcq 6*8(%[src]),%[res]\n\t"
				    "adcq 7*8(%[src]),%[res]\n\t"
				    "adcq %[zero],%[res]"
				    : [res] "=r" (result)
				    : [src] "r" (buff), [zero] "r" (zero),
				    "[res]" (result));
				buff += 64;
				count64--;
			}

			/* last up to 7 8byte blocks */
			count %= 8; 
			while (count) { 
				asm("addq %1,%0\n\t"
				    "adcq %2,%0\n" 
					    : "=r" (result)
				    : "m" (*(unsigned long *)buff), 
				    "r" (zero),  "0" (result));
				--count; 
					buff += 8;
			}
			result = add32_with_carry(result>>32,
						  result&0xffffffff); 

			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = add32_with_carry(result>>32, result & 0xffffffff); 
	if (odd) { 
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return result;
}

/**
 * csum_partial - Compute an internet checksum.
 * @buff: buffer to be checksummed
 * @len: length of buffer.
 * @sum: initial sum to be added in (32bit unfolded)
 *
 * Computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * This function must be called with even lengths, except
 * for the last fragment, which may be odd.
 * It's best to have buff aligned on a 64-bit boundary
 *
 * Returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 */
unsigned int csum_partial(const void *buff, int len, unsigned int sum)
{
	return add32_with_carry(do_csum(buff, len), sum);
}
