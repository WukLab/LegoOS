#include "includeme.h"

int main(void)
{
	unsigned long base;

	base = (unsigned long)malloc(PAGE_SIZE*256);

	base = (base + PAGE_SIZE) & ~(PAGE_SIZE-1);
	printf("base: %#lx\n", base);

	munmap((void *)base, PAGE_SIZE*16);

	return 0;
}
