#
# Trampoline code for booting secondary cpus
#

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

TRAMPOLINE_OBJS = $(obj)/ld.lds $(obj)/trampoline.o

targets := $(patsubst $(obj)/%,%,$(TRAMPOLINE_OBJS))

$(obj)/trampoline: $(TRAMPOLINE_OBJS) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_trampoline.bin :=  -O binary -R .comment -R .note -S
$(obj)/trampoline.bin: $(obj)/trampoline FORCE
	$(call if_changed,objcopy)
