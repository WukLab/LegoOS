KBUILD_CFLAGS := $(REALMODE_CFLAGS) -D__SETUP__
KBUILD_AFLAGS := $(KBUILD_CFLAGS) -D__ASSEMBLY__

targets	:= vmImage.bin setup.bin setup.elf bzImage

#
# The setup image
#
setup-y := header.o main.o bioscall.o tty.o printf.o version.o regs.o string.o

targets	+= $(setup-y)

#
# The tool to concatenate all images
#
hostprogs-y	:= tools/build
HOST_EXTRAFLAGS	+= -I$(srctree)/tools/include \
		   -include include/generated/autoconf.h

quiet_cmd_bzImage = BUILD   $@
cmd_bzImage = $(obj)/tools/build $(obj)/setup.bin $(obj)/vmImage.bin $@

$(obj)/bzImage: $(obj)/setup.bin $(obj)/vmImage.bin $(obj)/tools/build FORCE
	$(call if_changed,bzImage)
	@echo 'Kernel: $@ is ready' ' (#'`cat .version`')'

OBJCOPYFLAGS_vmImage.bin := -O binary -R .note -R .comment -S
$(obj)/vmImage.bin: $(obj)/vmImage FORCE
	$(call if_changed,objcopy)

AFLAGS_header.o += -I$(objtree)/$(obj)
$(obj)/header.o:

SETUP_OBJS = $(addprefix $(obj)/,$(setup-y))
LDFLAGS_setup.elf := -T
$(obj)/setup.elf: $(src)/setup.ld $(SETUP_OBJS) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_setup.bin := -O binary
$(obj)/setup.bin: $(obj)/setup.elf FORCE
	$(call if_changed,objcopy)

install:
	sh $(srctree)/$(src)/install.sh $(KERNELRELEASE) $(obj)/bzImage \
	System.map "$(INSTALL_PATH)"
