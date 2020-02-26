#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <linux/unistd.h>
#include <string.h>

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

static void lego_test_dummy_get(void)
{
    printf("Testing syscall dummy_get\n");
    long retval = syscall(666, 2333);
    printf("dummy_get returns: %ld\n", retval);
}

static void lego_test_state_save(void)
{
    printf("Testing syscall state_save\n");
    char * name = "Bob's function233";
    char * state = "Bob went to 0xFB1DBA5 and ordered a cup of d2330241.";
    long retval = syscall(667, name, strlen(name)+1, strlen(state)+1, state);
    printf ("state_save returns: %ld\n", retval);
}

#define BUFFER_SIZE 1024
static void lego_test_state_load(void)
{
    printf("Testing syscall state_load\n");
    char * name = "Bob's function233";
    char buf[BUFFER_SIZE] = {0,};
    long retval = syscall(668, name, strlen(name)+1, BUFFER_SIZE, buf);
    printf ("state_load returns: %ld, retrieved state is: %s\n", retval, buf);
}

int main(void)
{
	printf("pid: %d\n", getpid());
	lego_time();

//	lego_uname();
//	lego_getrlimit();
//	lego_set_tid_address();
//
//	lego_time();

    lego_test_dummy_get();
    lego_test_state_save();
    lego_test_state_load();
}

