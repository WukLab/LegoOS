#include "includeme.h"

int main(void)
{
	unsigned long base;

	base = (unsigned long)malloc(PAGE_SIZE*256);

	base = (base + PAGE_SIZE) & ~(PAGE_SIZE-1);
	printf("base: %#lx\n", base);
	*(int *)base = 66;

	munmap((void *)base, PAGE_SIZE);

	*(int *)(base + 0x60) = 66;

	printf("Lego munmap() BUG! Should not reach here!\n");
	return 0;
}
