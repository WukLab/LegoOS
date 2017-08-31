#include <signal.h>
#include <stdio.h>
#include <string.h>

static void hdl(int sig, siginfo_t *siginfo, void *context)
{
	printf("  Handler: sig: %d\n", sig);
	printf("  Handler: Sending PID: %ld, UID: %ld\n",
		(long)siginfo->si_pid, (long)siginfo->si_uid);

	printf("  Handler: Current-PID: %d\n", getpid());
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

	fprintf(stderr, "Before sending signal\n");
	kill(getpid(), SIGINT);
	fprintf(stderr, "After sending signal\n");

	return 0;
}
