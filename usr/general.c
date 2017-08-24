#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <linux/unistd.h>

static void lego_uname(void)
{
	struct utsname foo;

	uname(&foo);
	printf("uname(): \n"
	       "\t sysname: %s\n"
	       "\t nodename: %s\n"
	       "\t release: %s\n"
	       "\t version: %s\n"
	       "\t machine: %s\n",
	       foo.sysname, foo.nodename, foo.release, foo.version, foo.machine);
}

static void lego_getrlimit(void)
{
	struct rlimit l;

	getrlimit(RLIMIT_STACK, &l);
	printf("getrlimit(): RLIMIT_STACK, cur: %lld, max: %lld\n",
		l.rlim_cur, l.rlim_max);
}

static void lego_time(void)
{
	struct timeval tv;
	time_t t;

	gettimeofday(&tv, NULL);
	printf("gettimeofday(): tv_sec: %lld, tv_usec: %lld\n",
		tv.tv_sec, tv.tv_usec);

	t = time(NULL);	
	printf("time(NULL): %lld\n", t);
}

static void lego_set_tid_address(void)
{
	pid_t tgid;
	int dummy;

	tgid = syscall(218, &dummy);
	printf("set_tid_address(): return tgid: %u\n", tgid);
}

int main(void)
{
	printf("pid: %d\n", getpid());
	lego_time();

	lego_uname();
	lego_getrlimit();
	lego_set_tid_address();

	lego_time();
}
