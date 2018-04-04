/*
 * Test execv() SYSCALL
 */
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>

static char buf[8192];

static void dumpit(char *f_name)
{
	int fd;

	fd = open(f_name, 0);
	if (fd < 0) {
		perror("open");
		printf("Fail to open: %s\n", f_name);
		return;
	}

	memset(buf, 0, 8192);
	read(fd, buf, 8192);
	printf("%s\n", f_name);
	printf("%s\n", buf);

	close(fd);
}

int main(void)
{
	char *fname = "/root/ys/phoenix/phoenix-2.0/tests/word_count/word_count-pthread";
	//char *fname = "/root/ys/LegoOS/usr/pcache_conflict.o";
        char * const argv[] = { 
                fname,
		"/root/ys/phoenix/phoenix-2.0/tests/word_count/word_count_datafiles/word_1GB.txt",
                NULL,
        };

        setbuf(stdout, NULL);

	//dumpit("/proc/meminfo");
        printf("Before execv\n");

        if (!fork()){
		execv(fname, argv);
		printf("BUG!\n");
		return 0;
	} else
		wait(NULL);

        printf("After execv\n");
	//dumpit("/proc/meminfo");

        return 0;
}
