#include <lego/linkage.h>

ENTRY(_start)
1:
	hlt
	jmp 1b
END(_start)
