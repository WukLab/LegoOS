obj-m := fit.o

fit-y += fit_ibapi.o fit_internal.o

cflags += -g
EXTRA_CFLAGS += -g

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
