#include <pthread.h>
#include "../includeme.h"

static void *thread_func(void *unused)
{
	int tid = gettid();

	printf("  thread %d is running\n", tid);
	sleep(3);
	sleep(3);
	sleep(3);
}

int main(void)
{
	pthread_t tid;
	pthread_attr_t attr;
	int ret;

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	ret = pthread_create(&tid, &attr, thread_func, NULL);
	if (ret)
		die("Unable to create thread");

	printf("Before Join. Time: %d\n", time(NULL));
	pthread_join(tid, NULL);
	printf("After Join. Time: %d\n", time(NULL));

	return 0;
}
