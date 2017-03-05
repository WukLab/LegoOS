# Need this to let make clean work
subdir- := rm/

obj-y := piggy.o

$(obj)/piggy.o : $(obj)/rm/trampoline.bin

$(obj)/rm/trampoline.bin: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/rm $@
