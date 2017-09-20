#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

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

void one_gig(char c, int thread)
{
	char *mm, *end;
	unsigned long nr_size = 1024*1024*1024;
	mm = malloc(nr_size);
	end = mm + nr_size;
	mm = (char *) addr2vfn((unsigned long)mm);

	while (mm < end) {
		if (addr2set((unsigned long)mm) == 0) {
			printf("thread: %d addr in 0 set is %lx\n",thread, mm);
			(*mm) = c; 
		}
		mm += PAGE_SIZE;
	}
}

void thread1()
{
	one_gig('y', 1);
	one_gig('i', 1);
	one_gig('l', 1);
}

void thread2()
{
	one_gig('c', 2);
	one_gig('h', 2);
	one_gig('e', 2);
}

void main()
{
	pthread_t tid1, tid2; 
	pthread_create(&tid1, NULL, thread1, NULL);
	pthread_create(&tid2, NULL, thread2, NULL);

	pthread_join(tid1, NULL);
	pthread_join(tid2, NULL);
	return;
}
