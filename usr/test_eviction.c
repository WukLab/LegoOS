#include <stdio.h>
#include <stdlib.h>


#define NR_BITS 12
#define SET_MASK ((1ULL << 28) - 1) 

#define PAGE_SIZE 4096

unsigned long addr2set(unsigned long addr)
{
	return (addr & SET_MASK) >> NR_BITS;
}

unsigned long addr2vfn(unsigned long addr)
{
	return (addr >> NR_BITS) << NR_BITS;
}

void one_gig(char c)
{
	char *mm, *end;
	unsigned long nr_size = 1024*1024*1024;
	mm = malloc(nr_size);
	end = mm + nr_size;
	mm = (char *) addr2vfn((unsigned long)mm);

	while (mm < end) {
		if (addr2set((unsigned long)mm) == 0) {
			printf("addr in 0 set is %lx\n", mm);
			(*mm) = c; 
		}
		mm += PAGE_SIZE;
	}
}

void main()
{
	one_gig('y');
	one_gig('i');
	one_gig('l');
}
