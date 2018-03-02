/*
 * Test:
 * pthread_create -> clone
 * gettid
 * getcpu
 */

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>

static pid_t gettid(void)
{
	syscall(SYS_gettid);
}

void getcpu(int *cpu, int *node)
{
	int ret;

	ret = syscall(SYS_getcpu, cpu, node, NULL);
	perror("");
}

static void *thread_1(void *arg)
{
	int cpu, node;

	getcpu(&cpu, &node);
	printf("In %s(), pid: %d, tid: %d CPU:%d NODE:%d\n",
		__func__, getpid(), gettid(), cpu, node);
}

int main(void)
{
	int ret;
	pthread_t tid;
	int cpu, node;
	
	setbuf(stdout, NULL);

	getcpu(&cpu, &node);
	printf("In %s(), pid: %d, tid: %d CPU:%d NODE:%d\n",
		__func__, getpid(), gettid(), cpu, node);

	ret = pthread_create(&tid, NULL, thread_1, NULL);
	if (ret) {
		printf("pthread_create failed\n");
		exit(-1);
	}
	pthread_join(tid, NULL);
	printf("new thread id is: %u\n", tid);
}
