#include "includeme.h"

static int set_conflict(void)
{
	void *foo;
	int i, j;
	unsigned long stride;

	foo = malloc((long)1024*1024*1024*20);
	if (!foo)
		die("fail to alloc");

	stride = 0x10000000;
	for (i = 0; i < 20; i++) {
		void *ptr = foo + i * stride;

		printf("ptr: %p\n", ptr);
		j = *(int *)(ptr);
	}
}

int main(void)
{
	set_conflict();
}
