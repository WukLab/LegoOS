obj-m := test_send.o

cflags += -g
EXTRA_CFLAGS += -g

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions *~
