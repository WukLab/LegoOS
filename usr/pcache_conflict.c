#include "includeme.h"

#include <uapi/processor/pcache.h>

struct pcache_stat pstat;

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

/* write to the first cacheline to test eviction */
static void *thread_func(void *arg)
{
	int *wl;

	wl = (int *)base;
	while (1) {
		int i = 0;

		while (i < 100000) i++;
		*wl = 100;
	}
}

static int test_set_conflict(void)
{
	int i, j, ret;
	unsigned long stride;
	pthread_t tid;

	base = malloc((long)1024*1024*1024*20);
	BUG_ON(!base);

	/* Should get this from syscall or /proc file */
	stride = 0x10000000;

	base = (void *)round_up((unsigned long)base, PAGE_SIZE);

	ret = pthread_create(&tid, NULL, thread_func, NULL);
	if (ret)
		die("fail to create new thread");

	for (i = 0; i < nr_lines; i++) {
		void *ptr = base + i * stride;
		unsigned int csum;

		csum = page_fill_random(ptr);
		printf("(Generate) %d address: (%p) csum: (%#lx)\n",
			i, ptr, csum);
	}

	for (i = 0; i < nr_lines; i++) {
		void *ptr = base + i * stride;
		unsigned int csum;

		csum = csum_partial(ptr, PAGE_SIZE, 0);
		printf("(Verify) %d address: (%p) csum: (%#lx)\n",
			i, ptr, csum);
	}
	pthread_join(tid, NULL);
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
	srand(time(NULL));
	pcache_stat(&pstat);
	print_pstat(&pstat);
	test_set_conflict();
}
