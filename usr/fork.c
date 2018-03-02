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

	setbuf(stdout, NULL);

	getcpu(&cpu, &node);
	printf("Parent before fork: pid: %d, tid: %d CPU:%d NODE:%d\n",
		getpid(), gettid(), cpu, node);
	printf("CPU page: %#lx a page: %#lx\n", (unsigned long)&cpu & PAGE_MASK, (unsigned long)&a & PAGE_MASK);

	pid = fork();
	if (pid == 0) {
		a = 200;
		getcpu(&cpu, &node);
		printf("Child after fork: pid: %d, tid: %d CPU:%d NODE:%d a=%d\n",
			getpid(), gettid(), cpu, node, a);
		exit(1);
	} else {
		a = 400;
		getcpu(&cpu, &node);
		printf("Parent after fork: pid: %d, tid: %d CPU:%d NODE:%d a=%d\n",
			getpid(), gettid(), cpu, node, a);

	}

	return 0;
}
