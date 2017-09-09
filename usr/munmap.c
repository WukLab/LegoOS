#include "includeme.h"

int main(void)
{
	unsigned long base;
	int i, j;

	base = (unsigned long)malloc(PAGE_SIZE*256);

	base = (base + PAGE_SIZE) & ~(PAGE_SIZE-1);
	printf("base: %#lx\n", base);
	for (i = 0; i < 16; i++) {
		j = *(int *)(base+i*PAGE_SIZE);
	}

	munmap((void *)base, PAGE_SIZE*8);

	*(int *)(base + 0x60) = 66;

	printf("Lego munmap() BUG! Should not reach here!\n");
	return 0;
}
