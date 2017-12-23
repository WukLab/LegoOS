/*
 * Created by Yizhou Shan, Nov 2017
 * Used to test pcache eviction/flush/fill functionalities.
 * See detailed flow explanation below.
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
int nr_lines = 10;
unsigned int *csums;

/*
 * write to the first cacheline to test eviction
 */
static void *thread_func(void *arg)
{
	int *wl;

	wl = (int *)base;
	while (1) {
		*wl = 0x666666;
	}
}

static int test_set_conflict(void)
{
	int i, j, ret;
	unsigned long stride;
	pthread_t tid;

	base = malloc((long)1024*1024*1024*20);
	csums = malloc((sizeof(unsigned int)) * nr_lines);
	BUG_ON(!base || !csums);

	stride = pstat.way_stride;

	base = (void *)round_up((unsigned long)base, PAGE_SIZE);

	/*
	 * Flow:
	 *
	 * a)
	 * Walk through nr_line pages, and fill them with
	 * random generated numbers, save the checksum of each
	 * page to an array.
	 *
	 * During the walk through, some early touched pages will
	 * be flushed back to memory.
	 *
	 * In the second step, we again walk through the same set
	 * of pages, get the csum and compare with the saved ones.
	 * If anyone of them does not match, it means the underlying
	 * pcache_flush has corrupted memory.
	 *
	 * b)
	 * There is another thread trying to write to the first page
	 * all the time, which is used to test the clflush intergity
	 * feature. During clflush, the page is marked as RO. So the
	 * other thread should have a pgfault of permission failed.
	 *
	 * It should be taken care of by pcache_do_wp_page().
	 * After that, its mapping will be invalidated by pcache_flush,
	 * which means eventually it will have a non-present pgfault,
	 * or a pcache fill.
	 *
	 * Both features have been tested and work fine.
	 * The concern now comes to the performance.
	 */

	for (i = 0; i < nr_lines; i++) {
		void *ptr = base + i * stride;
		unsigned int csum;

		csum = page_fill_random(ptr);
		csums[i] = csum;
		printf("(Generate) %d address: (%p) csum: (%#x)\n",
			i, ptr, csum);
	}

	for (i = 0; i < nr_lines; i++) {
		void *ptr = base + i * stride;
		unsigned int csum;

		csum = csum_partial(ptr, PAGE_SIZE, 0);
		printf("(Verify) %d address: (%p) pcsum: (%#x) ccsum: (%#x)\n",
			i, ptr, csums[i], csum);
		if (csum != csums[i]) {
			printf(" %d Corrupted memory at %p, previous csum: %#x, current csum: %#x\n",
				i, ptr, csums[i], csum);
		}
	}
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
