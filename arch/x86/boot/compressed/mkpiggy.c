#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s compressed_file\n", argv[0]);
		return 1;
	}

	printf(".section \".compressed_kernel\",\"a\",@progbits\n");
	printf(".globl input_data, input_data_end\n");
	printf("input_data:\n");
	printf(".incbin \"%s\"\n", argv[1]);
	printf("input_data_end:\n");

	return 0;
}
