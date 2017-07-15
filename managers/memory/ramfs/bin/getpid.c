/*
 * Compile:
 *	gcc -static -Os getpid.c -o getpid
 */
#include <unistd.h>
int main(int argc, char **argv)
{
	getpid();
	return 0;
}
