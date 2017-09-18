#include "includeme.h"

int oneg(void)
{
	void *foo;
	long nr_size, i, nr_pages;
	struct timeval ts, te, result;

	fprintf(stderr, "One gig:\n");

	nr_size = 1024*1024*1024*1;
	foo = malloc(nr_size);
	if (!foo)
		die("fail to malloc");

	nr_pages = nr_size / PAGE_SIZE;
	fprintf(stderr, "  Range: [%#lx - %#lx]\n", foo, foo + nr_pages * PAGE_SIZE);

	gettimeofday(&ts, NULL);
	for (i = 0; i < nr_pages; i++) {
		int *bar, cut;

		bar = foo + PAGE_SIZE * i;
		cut = *bar;
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	printf("  Runtime: %ld.%ld s\n",
		result.tv_sec, result.tv_usec/1000);
	return 0;
}

int main(void)
{
	oneg();
	oneg();
	oneg();
}
