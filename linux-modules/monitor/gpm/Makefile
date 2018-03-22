obj-m := lego_gpm.o

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../../../include

KBUILD_EXTRA_SYMBOLS += $(shell pwd)/../../fit/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(shell pwd)/../gmm/Module.symvers
export KBUILD_EXTRA_SYMBOLS

# Targets
all:	
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
help:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) help
