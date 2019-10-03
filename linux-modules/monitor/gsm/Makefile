obj-m := lego_gsm.o
lego_gsm-y := core.o hlist.o handlers.o

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../../../include

cflags += -g
EXTRA_CFLAGS += -g
KBUILD_EXTRA_SYMBOLS += $(shell pwd)/../../fit/Module.symvers
export KBUILD_EXTRA_SYMBOLS

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions *~
