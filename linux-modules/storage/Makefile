obj-m := storage.o
storage-y := core.o handlers.o file_ops.o

cflags += -g
EXTRA_CFLAGS += -g
KBUILD_EXTRA_SYMBOLS += $(shell pwd)/../fit/Module.symvers
export KBUILD_EXTRA_SYMBOLS

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions *~
