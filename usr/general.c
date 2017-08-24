#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>

static int lego_uname(void)
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

static int lego_getrlimit(void)
{
	struct rlimit l;

	getrlimit(RLIMIT_STACK, &l);
	printf("getrlimit(): RLIMIT_STACK, cur: %lld, max: %lld\n",
		l.rlim_cur, l.rlim_max);
}

static int lego_time(void)
{
	struct timeval tv;
	time_t t;

	gettimeofday(&tv, NULL);
	printf("gettimeofday(): tv_sec: %lld, tv_usec: %lld\n",
		tv.tv_sec, tv.tv_usec);

	t = time(NULL);	
	printf("time(NULL): %lld\n", t);

}

int main(void)
{
	lego_time();

	lego_uname();
	lego_getrlimit();

	lego_time();
}
