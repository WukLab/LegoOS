obj-m := fit.o

fit-y := fit_ibapi.o
fit-y += fit_internal.o
fit-y += fit_machine.o

cflags += -g

#
# It's not good to disable those warnings.
# Well.
#
EXTRA_CFLAGS += -g  -Wno-unused-variable -Wno-declaration-after-statement -Wno-format -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	@echo -e "\e[00;31m****"
	@echo "****    WARNING"
	@echo "****       Compiled with -g option"
	@echo -e "****\e[00m"

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
