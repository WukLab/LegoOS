obj-y := common.o intel.o
obj-y += scattered.o
obj-$(CONFIG_X86_FEATURE_NAMES) += capflags.o powerflags.o
obj-y += topology.o

ifdef CONFIG_X86_FEATURE_NAMES
quiet_cmd_mkcapflags = MKCAP   $@
      cmd_mkcapflags = $(CONFIG_SHELL) $(srctree)/$(src)/mkcapflags.sh $< $@

cpufeature = $(src)/../../include/asm/processor-features-flags.h

targets += capflags.c
$(obj)/capflags.c: $(cpufeature) $(src)/mkcapflags.sh FORCE
	$(call if_changed,mkcapflags)
endif
clean-files += capflags.c
