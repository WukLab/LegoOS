#define _GNU_SOURCE
#include "includeme.h"
#include <sys/mman.h>

#define MREMAP_MAYMOVE 1

int main(void)
{
	void *base;
	void *new_addr;

	base = mmap(NULL, PAGE_SIZE*8, PROT_WRITE | PROT_READ,
		MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	printf("mmap returned base: %p\n", base);

	/* Shrink from 8 pages to 4 pages */
	new_addr = mremap(base, PAGE_SIZE*8, PAGE_SIZE*4, MREMAP_MAYMOVE);
	printf("mremap(): new_addr: %#lx\n", new_addr);
	if (new_addr == MAP_FAILED) {
		perror("mremap");
		return -1;
	}

	*(int *)(new_addr + PAGE_SIZE*5) = 66;
	printf("mremap() BUG! Should have segfault!\n");

	return 0;
}
