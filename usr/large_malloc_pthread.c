#include "includeme.h"

#define RUN_SIZE	(1024*1024*128)
#define NR_THREADS	8

static int check_page(void *page)
{
	int i, *foo, bar;

	foo = page;
	for (i = 0; i < PAGE_SIZE/sizeof(int); i++) {
		bar = *foo++;
		if (bar) {
			fprintf(stderr, "BUG Caught: bar=%d\n", bar);
			die("die");
		}
	}
}

/* Touch 1 gigabyte memory */
int run(void)
{
	void *foo;
	long nr_size, i, nr_pages;
	struct timeval ts, te, result;

	fprintf(stderr, "One gig:\n");

	nr_size = RUN_SIZE;
	foo = malloc(nr_size);
	if (!foo)
		die("fail to malloc");

	nr_pages = nr_size / PAGE_SIZE;
	fprintf(stderr, "%d  Range: [%#lx - %#lx]\n",
		gettid(), foo, foo + nr_pages * PAGE_SIZE);

	gettimeofday(&ts, NULL);
	for (i = 0; i < nr_pages; i++) {
		int *bar;

		bar = foo + PAGE_SIZE * i;
		check_page(bar);
	}
	gettimeofday(&te, NULL);
	timeval_sub(&result, &te, &ts);

	printf("%d  Runtime: %ld.%ld s\n",
		gettid(), result.tv_sec, result.tv_usec/1000);
	return 0;
}

static void *thread_func(void *arg)
{
	printf("%d running\n", gettid());
	run();
	run();
	run();
}

int main(void)
{
	int i, ret;
	pthread_t tid[NR_THREADS];
	int nr_threads = NR_THREADS;

	printf("Configuration: nr_threads=%d, each_thread touch: %lx size\n",
		nr_threads, RUN_SIZE);

	for (i = 0; i < nr_threads; i++) {
		ret = pthread_create(&tid[i], NULL, thread_func, NULL);
		if (ret)
			die("fail to create new thread");
	}

	for (i = 0; i < nr_threads; i++) {
		pthread_join(tid[i], NULL);
	}

	printf("main() exit\n");
	return 0;
}
