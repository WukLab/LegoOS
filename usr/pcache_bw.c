/*
 * Created by Yizhou Shan, Jan 29 2018
 * Used to test pcache bandwidth
 *
 * Data integrity is verified by pcache_conflict.c
 */

#include "includeme.h"

#include <uapi/processor/pcache.h>

static struct pcache_stat pstat;

/* Fill page with random number and return checksum */
static unsigned int page_fill_random(int *ptr)
{
	int i, *foo = ptr;
	unsigned int csum;

	if ((unsigned long)ptr & ~PAGE_MASK) {
		printf("ptr: %p", ptr);
		BUG_ON((unsigned long)ptr & ~PAGE_MASK);
	}

	for (i = 0; i < (PAGE_SIZE / sizeof(int)); i++) {
		*ptr = rand();
		ptr++;
	}

	return csum_partial(foo, PAGE_SIZE, 0);
}

void *base;
int nr_lines = 16;
int nr_round = 3;

static int test_set_conflict(void)
{
	int i, j, ret;
	unsigned long stride;
	struct timeval ts, te, result;

	base = malloc((long)1024*1024*1024*20);
	BUG_ON(!base);

	stride = pstat.way_stride;
	//stride = 0x40000000;

	base = (void *)round_up((unsigned long)base, PAGE_SIZE);

	printf("Before access\n");
	gettimeofday(&ts, NULL);
	for (j = 0; j < nr_round; j++) {
		for (i = 0; i < nr_lines; i++) {
			void *ptr = base + i * stride;

			printf("round: %d, line: %d, ptr: %p\n", j, i, ptr);
			*(int *)ptr = 0x12345678;
		}
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	printf("  Runtime: %ld.%ld s\n", result.tv_sec, result.tv_usec/1000);
}

void print_pstat(struct pcache_stat *pstat)
{
	printf("%lu-way nr_cachelines: %lu nr_cachesets: %lu "
		"stride: %#lx line_size: %#lx\n",
		pstat->associativity,
		pstat->nr_cachelines, pstat->nr_cachesets,
		pstat->way_stride, pstat->cacheline_size);
}

int main(void)
{
	setbuf(stdout, NULL);

	srand(time(NULL));

	pcache_stat(&pstat);
	print_pstat(&pstat);

	test_set_conflict();
}
