#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <assert.h>

/* 1 writer, 2 reader */
int test_slow_write_fast_read(void)
{
	int pipefd[2];
	pid_t pid;
	const char chs[10] = {'a', 'b', 'c', 'd', 'e',
			'f', 'g', 'h', 'i', 'j'};
	
	printf("%s: \n", __func__);
	
	if (pipe(pipefd) == -1) {
		perror("Pipe: ");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid == -1) {
		perror("Fork: ");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		/* child */
		pid_t gcpid;
		ssize_t ret;
		char buf[5];
		int i;

		close(pipefd[1]);
		gcpid = fork();
		if (gcpid == -1) {
			perror("Child fork: ");
			exit(EXIT_FAILURE);
		}
		
		for (i = 0; i < 10; i++) {
			ret = read(pipefd[0], buf, 5);
			if (ret > 0) {
				printf("PID: %d read %ld bytes, buf: %c, %c, %c, %c, %c\n",
					getpid(), ret, buf[0], buf[1], buf[2], buf[3], buf[4]);
			}
		}
		close(pipefd[0]);
		_exit(EXIT_SUCCESS);
	} else {
		/* parent write slowly */
		int i, j;
		ssize_t ret;
		
		close(pipefd[0]);
		for (i = 0; i < 10; i++) {
			j = 0;
			do {
				j++;
			} while(j < 300000000);

			ret = write(pipefd[1], chs, 10);
			if (ret > 0) {
				printf("PID: %d write %ld bytes\n", getpid(), ret);
			}
		}
		waitid(P_ALL, pid, NULL, 0);
		close(pipefd[1]);
	}
	return 0;
}

char la_buf[10000];


/* fast write, slightly slower reader */
int test_fast_write_slow_read()
{
	int pipefd[2];
	pid_t pid;
	const char chs[10] = {'a', 'b', 'c', 'd', 'e',
			'f', 'g', 'h', 'i', 'j'};
	int tmp;

	printf("%s: \n", __func__);
	
	if (pipe(pipefd) == -1) {
		perror("Pipe: ");
		exit(EXIT_FAILURE);
	}

	for (tmp = 0; tmp < 10000; tmp += 10) {
		memcpy(la_buf + tmp, chs, 10);
	}

	pid = fork();
	if (pid == -1) {
		perror("Fork: ");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		/* child */
		ssize_t ret;
		char buf[5];
		int i, j;

		close(pipefd[1]);
	
		/* 100000 loop is enough to trigger boundaries case */
		for (i = 0; i < 100000; i++) {
			/* slower reader */
			j = 0;
			do {
				j++;
			} while(j < 50000);
			ret = read(pipefd[0], buf, 5);
			if (ret > 0) {
				assert(!memcmp(buf, "abcde", 5) ||
					!memcmp(buf, "fghij", 5));
			}
		}
		close(pipefd[0]);
		_exit(EXIT_SUCCESS);
	} else {
		int i, j;
		ssize_t ret;
		
		close(pipefd[0]);
		for (i = 0; i < 100000; i++) {
			ret = write(pipefd[1], la_buf, 10000);
			if (ret > 0) {
				printf("PID: %d write %ld bytes\n", getpid(), ret);
			}
			/* writer sleep is expected here */
			/* SIGPIPE is expected here */
		}
		waitid(P_ALL, pid, NULL, 0);
		close(pipefd[1]);
	}
	return 0;
}

void sigpipe_sighand(void)
{
	printf("PID: %d get SIGPIPE!!\n", getpid());
	exit(EXIT_FAILURE);
}

int main()
{
	if (signal(SIGPIPE, (void (*)(int)) sigpipe_sighand) == SIG_ERR) {
		perror("Fail to register SIGPIPE handler: ");
		exit(EXIT_FAILURE);
	}

	test_slow_write_fast_read();
	test_fast_write_slow_read();
	return 0;
}
