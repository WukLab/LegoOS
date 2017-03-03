obj-y := piggy.o

$(obj)/piggy.o : $(obj)/trampoline/trampoline.bin

$(obj)/trampoline/trampoline.bin: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/trampoline $@
