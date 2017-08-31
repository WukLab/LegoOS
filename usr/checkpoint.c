#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/unistd.h>

#define __NR_CHECKPOINT	666

static pid_t gettid(void)
{
	syscall(SYS_gettid);
}

static void *thread_1(void *arg)
{
	printf("In %s(), pid: %d, tid: %d \n",
		__func__, getpid(), gettid());
	for (;;);
}

static void *thread_2(void *arg)
{
	printf("In %s(), pid: %d, tid: %d \n",
		__func__, getpid(), gettid());
	for (;;);
}

static inline void checkpoint_process(pid_t pid)
{
	long ret;

	ret = syscall(__NR_CHECKPOINT, pid);
	if (ret < 0)
		perror("checkpoint");
}

static void create_threads(void)
{
	pthread_t tid;
	int ret;

	printf("In %s(), pid: %d, tid: %d \n",
		__func__, getpid(), gettid());

	ret = pthread_create(&tid, NULL, thread_1, NULL);
	if (ret) {
		printf("pthread_create failed\n");
		exit(-1);
	}
	//pthread_join(tid, NULL);

	ret = pthread_create(&tid, NULL, thread_2, NULL);
	if (ret) {
		printf("pthread_create failed\n");
		exit(-1);
	}
	//pthread_join(tid, NULL);
}

int main(void)
{
	int fd;

	fd = open("/proc/cmdline", 0, 0);
	if (fd < 0) {
		perror("open");
		exit(-1);
	}

	fprintf(stderr, "pid: %d\n", getpid());

	create_threads();
	checkpoint_process(getpid());

	fprintf(stderr, "Done \n");
	return 0;
}
