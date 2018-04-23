obj-m := storage.o
storage-y := core.o handlers.o file_ops.o replica.o stat.o

LEGO_INCLUDE := -I$(M)/../../include

EXTRA_CFLAGS += -g $(LEGO_INCLUDE) -D_LEGO_STORAGE_SOURCE_
KBUILD_EXTRA_SYMBOLS += $(shell pwd)/../fit/Module.symvers
export KBUILD_EXTRA_SYMBOLS

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions *~
