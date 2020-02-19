obj-m := fit.o

fit-y := fit_ibapi.o
fit-y += fit_internal.o
fit-y += fit_machine.o

cflags += -g

#
# It's not good to disable those warnings.
# Well.
#
EXTRA_CFLAGS += -Wno-unused-variable -Wno-declaration-after-statement -Wno-format -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast \
		-Wno-error=incompatible-pointer-types

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules  2>compile_err.log

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm compile_err.log
