#define _GNU_SOURCE
#include "includeme.h"
#include <sys/mman.h>

#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

int main(void)
{
	void *base;
	void *new_addr;
	int i;

	base = mmap(NULL, PAGE_SIZE*8, PROT_WRITE | PROT_READ,
		MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	printf("mmap returned base: %p\n", base);

	/* Shrink from 8 pages to 4 pages */
#if 0
	new_addr = mremap(base, PAGE_SIZE*8, PAGE_SIZE*4, MREMAP_MAYMOVE);
	printf("mremap(): new_addr: %#lx\n", new_addr);
	if (new_addr == MAP_FAILED) {
		perror("mremap");
		return -1;
	}

	*(int *)(new_addr + PAGE_SIZE*5) = 66;
	printf("mremap() BUG! Should have segfault!\n");
#endif

	/* Enlarge 8 pages to 1024 pages */
#if 0
	new_addr = mremap(base, PAGE_SIZE*8, PAGE_SIZE*1024, MREMAP_MAYMOVE);
	printf("mremap(): new_addr: %#lx\n", new_addr);
	if (new_addr == MAP_FAILED) {
		perror("mremap");
		return -1;
	}

	*(int *)(new_addr + PAGE_SIZE * 512) = 66;
	printf("mremap(): enlarge from 8 pages to 1024 pages work!\n");
#endif

	/*
	 * Strategy:
	 * 1) Before remap, write something into old base
	 * 2) remap base to new_addr
	 * 3) Check if new_addr has the value written in step 1)
	 * 4) Check if old base is still accessiable (BUG!)
	 */

	printf("Save some value into first 8 pages:\n");
	for (i = 0; i < 8; i++) {
		int j = rand();

		*(int *)(base + i * PAGE_SIZE) = j;
		printf("  %#lx, value: %d\n", base + i * PAGE_SIZE, j);
	}
	new_addr = mremap(base, PAGE_SIZE*8, PAGE_SIZE*4, MREMAP_MAYMOVE | MREMAP_FIXED,
			base - PAGE_SIZE * 1024);
	printf("mremap(): new_addr: %#lx\n", new_addr);
	if (new_addr == MAP_FAILED) {
		perror("mremap");
		return -1;
	}

	printf("Test if old pages are rempped\n");
	for (i = 0; i < 4; i++) {
		int j;
		
		j = *(int *)(new_addr + i * PAGE_SIZE);
		printf("  %#lx, value: %d\n", new_addr + i * PAGE_SIZE, j);
	}

	printf("Test if old base %#lx is invalidated (Segfault follows)\n", base);
	*(int *)(base) = 66;
	printf("mremap() BUG! Should have segfault!\n");

	i = 0;
	return 0;
}
