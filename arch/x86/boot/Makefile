#
# Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
#
# THE last Makefile, I promise.
#

# If you want to preset the SVGA mode, uncomment the next line and
# set SVGA_MODE to whatever number you want.
# Set it to -DSVGA_MODE=NORMAL_VGA if you just want the EGA/VGA mode.
# The number is the same as you would ordinarily press at bootup.
# Just search header.S for SVGA_MODE
SVGA_MODE	:= -DSVGA_MODE=NORMAL_VGA

KBUILD_CFLAGS := $(REALMODE_CFLAGS) -D__SETUP__
KBUILD_AFLAGS := $(KBUILD_CFLAGS) -D__ASSEMBLY__ $(SVGA_MODE)

targets	:= vmImage.bin setup.bin setup.elf bzImage

# Let clean descend into
subdir- := compressed

#
# The setup image
#
setup-y := header.o main.o bioscall.o tty.o printf.o version.o regs.o string.o \
           early_serial_console.o cmdline.o memory.o copy.o a20.o pm.o pmjump.o

# The link order of the video-*.o modules can matter.  In particular,
# video-vga.o *must* be listed first, followed by video-vesa.o.
# Hardware-specific drivers should follow in the order they should be
# probed, and video-bios.o should typically be last.
setup-y += video.o video-mode.o
setup-y += video-vga.o
setup-y += video-vesa.o
setup-y += video-bios.o

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
	@echo -e '\033[34mLegoOS Kernel: $@ is ready' ' (#'`cat .version`')\033[0m'
	@echo -e '\033[31mChecklist: '
	@echo -e '           - Serial'
	@echo -e '              - TTYS1'
	@echo -e '              - BOUD115200'
	@echo -e ''
	@echo -e '           - FIT'
	@echo -e '              - CONFIG_FIT_NR_NODES:  matched on all nodes'
	@echo -e '              - CONFIG_FIT_LOCAL_ID:  unique across nodes'
	@echo -e '              - CONFIG_SOCKET_O_IB:   same across nodes'
	@echo -e '              - fit_machine.c:        same across nodes'
	@echo -e ''
	@echo -e '            - Program'
	@echo -e '              - managers/processor/core.c: init_filename[]'
	@echo -e '\033[0m'

#
# This vmImage.bin has
# 1) compressed/head_$(BITS).o
# 2) original stripped vmImage kernel
#
OBJCOPYFLAGS_vmImage.bin := -O binary -R .note -R .comment -S
$(obj)/vmImage.bin: $(obj)/compressed/vmImage FORCE
	$(call if_changed,objcopy)

$(obj)/compressed/vmImage: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/compressed $@

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
