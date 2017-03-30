KBUILD_DEFCONFIG := x86_64_defconfig

CODE16GCC_CFLAGS := -m32 -Wa,$(srctree)/arch/x86/boot/code16gcc.h
M16_CFLAGS	 := $(call cc-option, -m16, $(CODE16GCC_CFLAGS))

REALMODE_CFLAGS	:= $(M16_CFLAGS) -g -Os -D__KERNEL__ \
		   -DDISABLE_BRANCH_PROFILING \
		   -Wall -Wstrict-prototypes -march=i386 -mregparm=3 \
		   -fno-strict-aliasing -fomit-frame-pointer -fno-pic \
		   -mno-mmx -mno-sse \
		   $(call cc-option, -ffreestanding) \
		   $(call cc-option, -fno-stack-protector) \
		   $(call cc-option, -mpreferred-stack-boundary=2)
export REALMODE_CFLAGS

# BITS is used as extension for files which are available in a 32 bit
# and a 64 bit version to simplify shared Makefiles.
# e.g.: obj-y += foo_$(BITS).o
export BITS

# Prevent GCC from generating any FP code by mistake.
#
# This must happen before we try the -mpreferred-stack-boundary, see:
#
#    https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53383
#
KBUILD_CFLAGS += -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
KBUILD_CFLAGS += $(call cc-option,-mno-avx,)

ifeq ($(CONFIG_X86_64),y)
BITS := 64
UTS_MACHINE := x86_64

biarch := -m64
KBUILD_AFLAGS += -m64
KBUILD_CFLAGS += -m64

# Align jump targets to 1 byte, not the default 16 bytes
KBUILD_CFLAGS += -falign-jumps=1

# Pack loops tightly as well:
KBUILD_CFLAGS += -falign-loops=1

# Don't autogenerate traditional x87 instructions
KBUILD_CFLAGS += $(call cc-option,-mno-80387)
KBUILD_CFLAGS += $(call cc-option,-mno-fp-ret-in-387)

# Use -mpreferred-stack-boundary=3 if supported.
KBUILD_CFLAGS += $(call cc-option,-mpreferred-stack-boundary=3)

# Use -mskip-rax-setup if supported.
KBUILD_CFLAGS += $(call cc-option,-mskip-rax-setup)

KBUILD_CFLAGS += -mno-red-zone
KBUILD_CFLAGS += -mcmodel=kernel

# -funit-at-a-time shrinks the kernel .text considerably
# unfortunately it makes reading oopses harder.
KBUILD_CFLAGS += $(call cc-option,-funit-at-a-time)

# this works around some issues with generating unwind tables in older gccs
# newer gccs do it by default
KBUILD_CFLAGS += $(call cc-option,-maccumulate-outgoing-args)
endif

LDFLAGS := -m elf_$(UTS_MACHINE)

# Speed up the build
KBUILD_CFLAGS += -pipe
# Workaround for a gcc prelease that unfortunately was shipped in a suse release
KBUILD_CFLAGS += -Wno-sign-compare
KBUILD_CFLAGS += -fno-asynchronous-unwind-tables

drivers-y	:= arch/x86/pci/
libs-y		:= arch/x86/lib/
core-y		:= arch/x86/kernel/
core-y		+= arch/x86/entry/
core-y		+= arch/x86/mm/
core-y		+= arch/x86/realmode/

boot = arch/x86/boot

PHONY += bzImage
all: bzImage

KBUILD_IMAGE := $(boot)/bzImage

#
# This vmImage is under top directory, and is the original kernel.
#
bzImage: vmImage
	$(Q)$(MAKE) $(build)=$(boot) $(KBUILD_IMAGE)
	$(Q)mkdir -p $(objtree)/arch/$(UTS_MACHINE)/boot
	$(Q)ln -fsn ../../x86/boot/bzImage $(objtree)/arch/$(UTS_MACHINE)/boot/$@

PHONY += install
install:
	$(Q)$(MAKE) $(build)=$(boot) $@

archprepare:
	$(Q)$(MAKE) $(build)=arch/x86/entry/syscalls all

archclean:
	$(Q)rm -rf $(objtree)/arch/i386
	$(Q)rm -rf $(objtree)/arch/x86_64
	$(Q)$(MAKE) $(clean)=$(boot)

define archhelp
  echo  '* bzImage      - Compressed kernel image (arch/x86/boot/bzImage)'
  echo  '  install      - Install kernel using'
  echo  '                  (your) ~/bin/$(INSTALLKERNEL) or'
  echo  '                  (distribution) /sbin/$(INSTALLKERNEL) or'
  echo  '                  install to $$(INSTALL_PATH) and run lilo'
endef
