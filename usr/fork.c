#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "includeme.h"

void getcpu(int *cpu, int *node)
{
	syscall(SYS_getcpu, cpu, node, NULL);
}

int main(void)
{
	int ret, cpu, node;
	pid_t pid;
	int a = 100;
	void *base;

	setbuf(stdout, NULL);

	getcpu(&cpu, &node);
	printf("Parent before fork: pid: %d, tid: %d CPU:%d NODE:%d\n",
		getpid(), gettid(), cpu, node);
	printf("CPU page: %#lx a page: %#lx\n", (unsigned long)&cpu & PAGE_MASK, (unsigned long)&a & PAGE_MASK);

	base = mmap(NULL, 4096*2, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (base == MAP_FAILED) {
		printf("Fail to mmap shared.\n");
		return 0;
	}
	*(int *)base = 66;

	pid = fork();
	if (pid == 0) {
		a = 200;
		getcpu(&cpu, &node);
		printf("Child after fork: pid: %d, tid: %d CPU:%d NODE:%d a=%d shared: %d\n",
			getpid(), gettid(), cpu, node, a, *(int *)base);

		/*
		 * Change the shared mapping's data
		 */
		*(int *)base = 77;
		exit(1);
	} else {
		a = 400;
		getcpu(&cpu, &node);

		/*
		 * Gracelly wait for child's change
		 */
		sleep(1);
		printf("Parent after fork: pid: %d, tid: %d CPU:%d NODE:%d a=%d shared: %d\n",
			getpid(), gettid(), cpu, node, a, *(int *)base);
	}

	return 0;
}
