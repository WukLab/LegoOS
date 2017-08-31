#include <signal.h>
#include <stdio.h>
#include <string.h>

static void hdl(int sig, siginfo_t *siginfo, void *context)
{
	printf("sig: %d\n", sig);
	printf("Sending PID: %ld, UID: %ld\n",
		(long)siginfo->si_pid, (long)siginfo->si_uid);

	exit(1);
}

int main()
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));

	act.sa_sigaction = &hdl;

	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGINT, &act, NULL) < 0) {
		perror("sigaction");
		return -1;
	}

	for (;;)
		sleep(1);

	return 0;
}
