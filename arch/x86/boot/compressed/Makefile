KBUILD_CFLAGS := -m$(BITS) -D__KERNEL__ $(LEGO_INCLUDE) -O2
KBUILD_CFLAGS += -fno-strict-aliasing
cflags-$(CONFIG_X86_32) := -march=i386
cflags-$(CONFIG_X86_64) := -mcmodel=small
KBUILD_CFLAGS += $(cflags-y)
KBUILD_CFLAGS += -mno-mmx -mno-sse
KBUILD_CFLAGS += $(call cc-option,-ffreestanding)
KBUILD_CFLAGS += $(call cc-option,-fno-stack-protector)

KBUILD_AFLAGS  := $(KBUILD_CFLAGS) -D__ASSEMBLY__

LDFLAGS := -m elf_$(UTS_MACHINE)
LDFLAGS_vmImage := -T

hostprogs-y := mkpiggy

VMIMAGE_OBJS = $(obj)/vmImage.lds $(obj)/head_64.o $(obj)/piggy.o

targets := vmImage vmImage.bin
targets += $(patsubst $(obj)/%,%,$(VMIMAGE_OBJS))

#
# This vmImage has:
# 1) head_$(BITS).o
# 2) vmImage.bin, which is the stripped kernel
#
$(obj)/vmImage: $(VMIMAGE_OBJS) FORCE
	$(call if_changed,ld)

#
# Generate the original 32-bit or 64-bit stripped kernel
#
OBJCOPYFLAGS_vmImage.bin :=  -O binary -R .comment -R .note -S
$(obj)/vmImage.bin: vmImage FORCE
	$(call if_changed,objcopy)

quiet_cmd_mkpiggy = MKPIGGY $@
      cmd_mkpiggy = $(obj)/mkpiggy $< > $@ || ( rm -f $@ ; false )

targets += piggy.S
$(obj)/piggy.S: $(obj)/vmImage.bin $(obj)/mkpiggy FORCE
	$(call if_changed,mkpiggy)
