#include "includeme.h"

/* Fill page with random number and return checksum */
static unsigned int page_fill_random(int *ptr)
{
	int foo, i, *base = ptr;
	unsigned int csum;

	if ((unsigned long)ptr & ~PAGE_MASK) {
		printf("ptr: %p", ptr);
		BUG_ON((unsigned long)ptr & ~PAGE_MASK);
	}

	for (i = 0; i < (PAGE_SIZE / sizeof(int)); i++) {
		*ptr = rand();
	}

	return csum_partial(base, PAGE_SIZE, 0);
}

static int test_set_conflict(void)
{
	void *foo;
	int i, j;
	unsigned long stride;

	foo = malloc((long)1024*1024*1024*20);
	if (!foo)
		die("fail to alloc");

	/* Should get this from syscall or /proc file */
	stride = 0x10000000;

	foo = (void *)round_up((unsigned long)foo, PAGE_SIZE);

	for (i = 0; i < 20; i++) {
		void *ptr = foo + i * stride;
		unsigned int csum;

		csum = page_fill_random(ptr);
		printf("(Generate) %d address: (%p) csum: (%#lx)\n",
			i, ptr, csum);
	}

	for (i = 0; i < 20; i++) {
		void *ptr = foo + i * stride;
		unsigned int csum;

		csum = csum_partial(ptr, PAGE_SIZE, 0);
		printf("(Verify) %d address: (%p) csum: (%#lx)\n",
			i, ptr, csum);
	}
}

int main(void)
{
	srand(time(NULL));
	test_set_conflict();
}
