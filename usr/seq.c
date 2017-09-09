/*
 * Test all /proc and /sys file output
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

static char *files[] = {
	"/proc/stat",
	"/proc/meminfo",
	"/proc/cmdline",
	"/proc/version",
	"/proc/processes",
	"/sys/devices/system/cpu/online",
};

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

int main()
{
	int i, fd;

	fd = open("/dev/tty", 0, 0);
	if (fd < 0) {
		perror("open /dev/tty");
		return;
	}
	printf("/dev/tty new fd: %d\n", fd);
	write(fd, "nihao", 5);

	for (i = 0; i < ARRAY_SIZE(files); i++)
		dumpit(files[i]);

	return 0;
}
