#
# Trampoline code for booting secondary cpus
#

KBUILD_CFLAGS := $(REALMODE_CFLAGS)
KBUILD_AFLAGS := $(KBUILD_CFLAGS) -D__ASSEMBLY__

LDFLAGS := -m elf_$(UTS_MACHINE)
LDFLAGS_trampoline.elf := -T

TRAMPOLINE_OBJS = $(obj)/ld.lds $(obj)/trampoline.o

targets := $(patsubst $(obj)/%,%,$(TRAMPOLINE_OBJS))
targets += trampoline.bin trampoline.elf

# This is the linked trampoline object
$(obj)/trampoline.elf: $(TRAMPOLINE_OBJS) FORCE
	$(call if_changed,ld)

# This is the binary will be embedded into kernel
OBJCOPYFLAGS_trampoline.bin :=  -O binary -R .comment -R .note -S
$(obj)/trampoline.bin: $(obj)/trampoline.elf FORCE
	$(call if_changed,objcopy)
