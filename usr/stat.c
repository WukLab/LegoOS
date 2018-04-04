#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

static int stat_fd(int fd, char *f_name)
{
    struct stat sb;

    if (fstat(fd, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    printf("fd: %d %s\n", fd, f_name ? f_name: " ");
    printf("File type:                ");

    switch (sb.st_mode & S_IFMT) {
    case S_IFBLK:  printf("block device\n");            break;
    case S_IFCHR:  printf("character device\n");        break;
    case S_IFDIR:  printf("directory\n");               break;
    case S_IFIFO:  printf("FIFO/pipe\n");               break;
    case S_IFLNK:  printf("symlink\n");                 break;
    case S_IFREG:  printf("regular file\n");            break;
    case S_IFSOCK: printf("socket\n");                  break;
    default:       printf("unknown?\n");                break;
    }

    printf("I-node number:            %ld\n", (long) sb.st_ino);

    printf("Mode:                     %lo (octal)\n",
            (unsigned long) sb.st_mode);

    printf("Link count:               %ld\n", (long) sb.st_nlink);
    printf("Ownership:                UID=%ld   GID=%ld\n",
            (long) sb.st_uid, (long) sb.st_gid);

    printf("Preferred I/O block size: %ld bytes\n",
            (long) sb.st_blksize);
    printf("File size:                %lld bytes\n",
            (long long) sb.st_size);
    printf("Blocks allocated:         %lld\n",
            (long long) sb.st_blocks);

    printf("Last status change:       %s", ctime(&sb.st_ctime));
    printf("Last file access:         %s", ctime(&sb.st_atime));
    printf("Last file modification:   %s", ctime(&sb.st_mtime));
    printf("\n\n");
}

static char *files[] = {
	"/proc/stat",
	"/proc/meminfo",
	"/dev/tty",
	"/sys/devices/system/cpu/online",
};

static void stat_f_name(char *f_name)
{
	int fd;

	fd = open(f_name, 0);
	if (fd < 0) {
		perror("open");
		printf("Fail to open: %s\n", f_name);
		return;
	}

	stat_fd(fd, f_name);
	close(fd);
}

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

int main(int argc, char *argv[])
{
	int i;

	for (i = 0; i < 3; i++)
		stat_fd(i, NULL);

	for (i = 0; i < ARRAY_SIZE(files); i++)
		stat_f_name(files[i]);

	return 0;
}
