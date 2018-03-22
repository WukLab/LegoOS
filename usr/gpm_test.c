#include <stdio.h>

int main(int argc, char** argv) {
	int i;
	printf("program start successfully\n");
	for (i = 0; i < argc; i++)
		printf("args[%d]: %s\n", i, argv[i]);
	printf("test program ends\n");
	return 0;
}
