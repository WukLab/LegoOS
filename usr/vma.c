/*
 * Compile:
 *	gcc -static -Os getpid.c -o getpid
 */
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
	int *ptr;
	int *newptr;
	printf("program starts\n");
	ptr = malloc(sizeof(int) * 3000000);
	newptr = realloc(ptr, sizeof(int) * 4000000);
	free(newptr);
	printf("looks good\n");
	return 0;
}
