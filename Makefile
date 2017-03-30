VERSION = 0
PATCHLEVEL = 0
SUBLEVEL = 1

# o Do not use make's built-in rules and variables
#   (this increases performance and avoids hard-to-debug behaviour);
# o Look for make include files relative to root of kernel src
MAKEFLAGS += -rR --include-dir=$(CURDIR)

# Beautify output
ifeq ("$(origin V)", "command line")
  KBUILD_VERBOSE = $(V)
endif
ifndef KBUILD_VERBOSE
  KBUILD_VERBOSE = 0
endif

ifeq ($(KBUILD_VERBOSE), 1)
  quiet =
  Q =
else
  quiet = quiet_
  Q = @
endif

export quiet Q KBUILD_VERBOSE

# kbuild supports saving output files in a separate directory.
# To locate output files in a separate directory two syntaxes are supported.
# In both cases the working directory must be the root of the kernel src.
# 1) O=
# Use "make O=dir/to/store/output/files/"
#
# 2) Set KBUILD_OUTPUT
# Set the environment variable KBUILD_OUTPUT to point to the directory
# where the output files shall be placed.
# export KBUILD_OUTPUT=dir/to/store/output/files/
# make
#
# The O= assignment takes precedence over the KBUILD_OUTPUT environment
# variable.

# KBUILD_SRC is set on invocation of make in OBJ directory
# KBUILD_SRC is not intended to be used by the regular user (for now)
ifeq ($(KBUILD_SRC),)

ifeq ("$(origin O)", "command line")
  KBUILD_OUTPUT := $(O)
endif

# Default target when none is given on the command line
PHONY := _all
_all:

# Cancel implicit rules on top Makefile
$(CURDIR)/Makefile Makefile: ;

ifneq ($(KBUILD_OUTPUT),)
# Invoke a second make in the output directory, passing relevant variables
# check that the output directory actually exists
saved-output := $(KBUILD_OUTPUT)
KBUILD_OUTPUT := $(shell mkdir -p $(KBUILD_OUTPUT) \
                   && cd $(KBUILD_OUTPUT) \
		   && /bin/pwd)

$(if $(KBUILD_OUTPUT),, \
     $(error failed to create output directory "$(saved-output)"))

PHONY += $(MAKECMDGOALS) sub-make

$(filter-out _all sub-make $(CURDIR)/Makefile, $(MAKECMDGOALS)) _all: sub-make
	@:

sub-make:
	$(Q)$(MAKE) -C $(KBUILD_OUTPUT) KBUILD_SRC=$(CURDIR) \
	-f $(CURDIR)/Makefile $(filter-out _all sub-make,$(MAKECMDGOALS))

# Leave processing to the above invocation of make
skip-makefile := 1
endif # ifneq ($(KBUILD_OUTPUT),)
endif # ifeq ($(KBUILD_SRC),)

# We process the rest of the Makefile if this is the final invocation of make
ifeq ($(skip-makefile),)

# Do not print "Entering directory ...",
# but we want to display it when entering to the output directory
MAKEFLAGS += --no-print-directory

# Use make M=dir to specify directory of external module to build
ifeq ("$(origin M)", "command line")
  KBUILD_EXTMOD := $(M)
endif

# If building an external module we do not care about the all: rule
# but instead _all depend on modules
PHONY += all
ifeq ($(KBUILD_EXTMOD),)
_all: all
else
_all: modules
endif

ifeq ($(KBUILD_SRC),)
        # building in the source tree
        srctree := .
else
        ifeq ($(KBUILD_SRC)/,$(dir $(CURDIR)))
                # building in a subdirectory of the source tree
                srctree := ..
        else
                srctree := $(KBUILD_SRC)
        endif
endif
objtree		:= .
src		:= $(srctree)
obj		:= $(objtree)

VPATH		:= $(srctree)$(if $(KBUILD_EXTMOD),:$(KBUILD_EXTMOD))

export srctree objtree VPATH

# SUBARCH tells the usermode build what the underlying arch is.
# ---------------------------------------------------------------------------
#
# If a native build is happening, then ARCH is assigned, getting whatever
# value it gets normally, and SUBARCH is subsequently ignored.
SUBARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/)

# Cross compiling and selecting different set of gcc/bin-utils
# ---------------------------------------------------------------------------
#
# When performing cross compilation for other architectures ARCH shall be set
# to the target architecture. (See arch/* for the possibilities).
# ARCH can be set during invocation of make:
# make ARCH=x86
# Another way is to have ARCH set in the environment.
# The default ARCH is the host where make is executed.

# CROSS_COMPILE specify the prefix used for all executables used
# during compilation. Only gcc and related bin-utils executables
# are prefixed with $(CROSS_COMPILE).
# CROSS_COMPILE can be set on the command line
# make CROSS_COMPILE=ia64-
# Alternatively CROSS_COMPILE can be set in the environment.
# A third alternative is to store a setting in .config so that plain
# "make" in the configured kernel build directory always uses that.
# Default value for CROSS_COMPILE is not to prefix executables
# Note: Some architectures assign CROSS_COMPILE in their arch/*/Makefile
ARCH		?= $(SUBARCH)
CROSS_COMPILE	?= $(CONFIG_CROSS_COMPILE:"%"=%)

# Architecture as present in compile.h
UTS_MACHINE 	:= $(ARCH)
SRCARCH 	:= $(ARCH)

# Additional ARCH settings for x86
ifeq ($(ARCH),i386)
        SRCARCH := x86
endif
ifeq ($(ARCH),x86_64)
        SRCARCH := x86
endif

KCONFIG_CONFIG ?= .config
export KCONFIG_CONFIG

# SHELL used by kbuild
CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	  else if [ -x /bin/bash ]; then echo /bin/bash; \
	  else echo sh; fi ; fi)

HOSTCC       = gcc
HOSTCXX      = g++
HOSTCFLAGS   = -Wall -Wmissing-prototypes -Wstrict-prototypes -O2 -fomit-frame-pointer -std=gnu89
HOSTCXXFLAGS = -O2

# Decide whether to build built-in, modular, or both.
# Normally, just do built-in.
KBUILD_MODULES :=
KBUILD_BUILTIN := 1

# If we have "make <whatever> modules", compile modules
# in addition to whatever we do anyway.
# Just "make" or "make all" shall build modules as well
ifneq ($(filter all _all modules,$(MAKECMDGOALS)),)
  KBUILD_MODULES := 1
endif

ifeq ($(MAKECMDGOALS),)
  KBUILD_MODULES := 1
endif

export KBUILD_MODULES KBUILD_BUILTIN
export KBUILD_SRC KBUILD_EXTMOD

# We need some generic definitions (do not try to remake the file).
scripts/Kbuild.include: ;
include scripts/Kbuild.include

# Make variables (CC, etc...)
AS		= $(CROSS_COMPILE)as
LD		= $(CROSS_COMPILE)ld
CC		= $(CROSS_COMPILE)gcc
CPP		= $(CC) -E
AR		= $(CROSS_COMPILE)ar
NM		= $(CROSS_COMPILE)nm
STRIP		= $(CROSS_COMPILE)strip
OBJCOPY		= $(CROSS_COMPILE)objcopy
OBJDUMP		= $(CROSS_COMPILE)objdump
PERL		= perl
PYTHON		= python
CHECK		= sparse
INSTALLKERNEL	= installkernel

CHECKFLAGS	= -D__Sandix__ -DSandix -D__STDC__ -Dunix -D__unix__ \
		  -Wbitwise -Wno-return-void

LEGO_INCLUDE	:= -I$(srctree)/arch/$(SRCARCH)/include \
                   $(if $(KBUILD_SRC), -I$(srctree)/include) \
		   -I$(objtree)/include \
		   -include $(srctree)/include/lego/kconfig.h

KBUILD_CPPFLAGS = -D__KERNEL__
NOSTDINC_FLAGS	=
LDFLAGS_vmImage	=

KBUILD_CFLAGS   := -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs \
		   -fno-strict-aliasing -fno-common \
		   -Werror-implicit-function-declaration \
		   -Wno-format-security \
		   -std=gnu89

KBUILD_AFLAGS	:= -D__ASSEMBLY__

# Read KERNELRELEASE from include/config/kernel.release (if it exists)
KERNELRELEASE = $(shell cat include/config/kernel.release 2> /dev/null)
KERNELVERSION = $(VERSION)$(if $(PATCHLEVEL),.$(PATCHLEVEL)$(if $(SUBLEVEL),.$(SUBLEVEL)))$(EXTRAVERSION)

export MAKE AS LD CC CPP AR NM STRIP OBJCOPY OBJDUMP PERL PYTHON CHECK INSTALLKERNEL CHECKFLAGS
export LEGO_INCLUDE KBUILD_CPPFLAGS KBUILD_CFLAGS KBUILD_AFLAGS NOSTDINC_FLAGS
export VERSION PATCHLEVEL SUBLEVEL KERNELRELEASE KERNELVERSION
export ARCH SRCARCH UTS_MACHINE CONFIG_SHELL HOSTCC HOSTCFLAGS CROSS_COMPILE

# ===========================================================================
# Rules shared between *config targets and build targets

# Basic helpers built in scripts/
PHONY += scripts_basic
scripts_basic:
	$(Q)$(MAKE) $(build)=scripts/basic
	$(Q)rm -f .tmp_quiet_recordmcount

# To avoid any implicit rule to kick in, define an empty command.
scripts/basic/%: scripts_basic ;

PHONY += outputmakefile
# outputmakefile generates a Makefile in the output directory, if using a
# separate output directory. This allows convenient use of make in the
# output directory.
outputmakefile:
ifneq ($(KBUILD_SRC),)
	$(Q)ln -fsn $(srctree) source
	$(Q)$(CONFIG_SHELL) $(srctree)/scripts/mkmakefile \
	    $(srctree) $(objtree) $(VERSION) $(PATCHLEVEL)
endif

# To make sure we do not include .config for any of the *config targets
# catch them early, and hand them over to scripts/kconfig/Makefile
# It is allowed to specify more targets when calling make, including
# mixing *config targets and build targets.
# For example 'make oldconfig all'.
# Detect when mixed targets is specified, and make a second invocation
# of make so .config is not included in this case either (for *config).

version_h := include/generated/version.h

no-dot-config-targets := clean mrproper distclean \
			 cscope gtags TAGS tags help% %docs check% coccicheck \
			 $(version_h) headers_% archheaders archscripts \
			 kernelversion %src-pkg

config-targets := 0
mixed-targets  := 0
dot-config     := 1

ifneq ($(filter $(no-dot-config-targets), $(MAKECMDGOALS)),)
	ifeq ($(filter-out $(no-dot-config-targets), $(MAKECMDGOALS)),)
		dot-config := 0
	endif
endif

ifeq ($(KBUILD_EXTMOD),)
        ifneq ($(filter config %config,$(MAKECMDGOALS)),)
                config-targets := 1
                ifneq ($(words $(MAKECMDGOALS)),1)
                        mixed-targets := 1
                endif
        endif
endif

ifeq ($(mixed-targets),1)
# ===========================================================================
# We're called with mixed targets (*config and build targets).
# Handle them one by one.

PHONY += $(MAKECMDGOALS) __build_one_by_one

$(filter-out __build_one_by_one, $(MAKECMDGOALS)): __build_one_by_one
	@:

__build_one_by_one:
	$(Q)set -e; \
	for i in $(MAKECMDGOALS); do \
		$(MAKE) -f $(srctree)/Makefile $$i; \
	done

else
ifeq ($(config-targets), 1)
# ===========================================================================
# *config targets only - make sure prerequisites are updated, and descend
# in scripts/kconfig to make the *config target.

# Read arch specific Makefile to set KBUILD_DEFCONFIG as needed.
# KBUILD_DEFCONFIG may point out an alternative default configuration
# used for 'make defconfig'
include arch/$(SRCARCH)/Makefile
export KBUILD_DEFCONFIG KBUILD_KCONFIG

config: scripts_basic outputmakefile FORCE
	$(Q)$(MAKE) $(build)=scripts/kconfig $@

%config: scripts_basic outputmakefile FORCE
	$(Q)$(MAKE) $(build)=scripts/kconfig $@


else
# ===========================================================================
# Build targets only - this includes vmImage, arch specific targets, clean
# targets and others. In general all targets except *config targets.

ifeq ($(KBUILD_EXTMOD),)
# Additional helpers built in scripts/
# Carefully list dependencies so we do not try to build scripts twice
# in parallel
PHONY += scripts
scripts: scripts_basic include/config/auto.conf include/config/tristate.conf
	$(Q)$(MAKE) $(build)=$(@)
endif # KBUILD_EXTMOD

ifeq ($(dot-config),1)
# Read in config
-include include/config/auto.conf

ifeq ($(KBUILD_EXTMOD),)
# Read in dependencies to all Kconfig* files, make sure to run
# oldconfig if changes are detected.
-include include/config/auto.conf.cmd

# To avoid any implicit rule to kick in, define an empty command
$(KCONFIG_CONFIG) include/config/auto.conf.cmd: ;

# It is important to know how Makefiles are remade and how 'include'
# directive works. Here are some words form GNU Make Manual:
#
# If a Makefile can be remade from other files, you probably want make to
# get an up-to-date version of the Makefile to read in. After reading in all
# Makefiles, make will consider each as a goal target and attempt to update
# it. If a Makefile has a rule which says how to update it(found either in
# that very Makefile or in other one) or if an implicit rule applies to it,
# it will be updated if necessary. After all Makefiles have been checked, if
# any have actually been changed, make starts with a clean slate and reads all
# the Makefiles again.
#
# If you know that one or more of your Makefiles can NOT be remade and you want
# to keep make from performing an implicit rule search on them, perhaps for
# effiency reasons, you can use any normal method of preventing implicit rule
# look-up to do so. For example, you can write an explicit rule wuth the
# Makefile as the target, and an empty recipe.
#
# '-q' and '-n' do not prevent updating of Makefiles, because an out-of-date
# Makefile would result in the wrong output for other targets.
###
# Here, we have an explicit rule for included file include/config/auto.conf.
# So before GNUmake read "auto.conf", it will checkout the dependencies of it.
#
# That is why in a clean tree, this target always got built even you invoke with
# a non-exsit target, for example, "make ABCDEF".
#
# If .config is newer than include/config/auto.conf, someone tinkered
# with it and forgot to run make oldconfig.
# if auto.conf.cmd is missing then we are probably in a cleaned tree so
# we execute the config step to be sure to catch updated Kconfig files
include/config/%.conf: $(KCONFIG_CONFIG) include/config/auto.conf.cmd
	$(Q)$(MAKE) -f $(srctree)/Makefile silentoldconfig
else
# external modules needs include/generated/autoconf.h and include/config/auto.conf
# but do not care if they are up-to-date. Use auto.conf to trigger the test
PHONY += include/config/auto.conf

include/config/auto.conf:
	$(Q)test -e include/generated/autoconf.h -a -e $@ || (		\
	echo >&2;							\
	echo >&2 "  ERROR: Kernel configuration is invalid.";		\
	echo >&2 "         include/generated/autoconf.h or $@ are missing.";\
	echo >&2 "         Run 'make oldconfig && make prepare' on kernel src to fix it.";	\
	echo >&2 ;							\
	/bin/false)
endif # KBUILD_EXTMOD

else
# Dummy target needed, because used as prerequisite
include/config/auto.conf: ;
endif # $(dot-config)

# The all: target is the default when no target is given on the command line.
# This allow a user to issue only 'make' to build a kernel including modules.
# Defaults to vmImage, but the arch Makefile will add further targets.
all: vmImage

# The arch Makefile can set ARCH_{CPP,A,C}FLAGS to override the default
# values of the respective KBUILD_* variables
ARCH_CPPFLAGS :=
ARCH_AFLAGS :=
ARCH_CFLAGS :=
include arch/$(SRCARCH)/Makefile

KBUILD_CFLAGS	+= $(call cc-option,-fno-delete-null-pointer-checks,)
KBUILD_CFLAGS	+= $(call cc-disable-warning,maybe-uninitialized,)
KBUILD_CFLAGS	+= $(call cc-disable-warning,frame-address,)

ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE
KBUILD_CFLAGS	+= -Os
else
KBUILD_CFLAGS	+= -O2
endif

# Tell gcc to never replace conditional load with a non-conditional one
KBUILD_CFLAGS   += $(call cc-option,--param=allow-store-data-races=0)

ifdef CONFIG_READABLE_ASM
# Disable optimizations that make assembler listings hard to read.
# reorder blocks reorders the control in the function
# ipa clone creates specialized cloned functions
# partial inlining inlines only parts of functions
KBUILD_CFLAGS += $(call cc-option,-fno-reorder-blocks,) \
                 $(call cc-option,-fno-ipa-cp-clone,) \
                 $(call cc-option,-fno-partial-inlining)
endif

ifneq ($(CONFIG_FRAME_WARN),0)
KBUILD_CFLAGS += $(call cc-option,-Wframe-larger-than=${CONFIG_FRAME_WARN})
endif

# Use make W=1 to enable them
KBUILD_CFLAGS += $(call cc-disable-warning, unused-but-set-variable)
KBUILD_CFLAGS += $(call cc-disable-warning, unused-const-variable)

ifdef CONFIG_FRAME_POINTER
KBUILD_CFLAGS	+= -fno-omit-frame-pointer -fno-optimize-sibling-calls
else
KBUILD_CFLAGS	+= -fomit-frame-pointer
endif

ifdef CONFIG_DEBUG_INFO
ifdef CONFIG_DEBUG_INFO_SPLIT
KBUILD_CFLAGS   += $(call cc-option, -gsplit-dwarf, -g)
else
KBUILD_CFLAGS	+= -g
endif
KBUILD_AFLAGS	+= -Wa,-gdwarf-2
endif


# arch Makefile may override CC so keep this after arch Makefile is included
NOSTDINC_FLAGS += -nostdinc -isystem $(shell $(CC) -print-file-name=include)
CHECKFLAGS     += $(NOSTDINC_FLAGS)

KBUILD_CFLAGS   += $(call cc-option, -fno-var-tracking-assignments)

# warn about C99 declaration after statement
KBUILD_CFLAGS += $(call cc-option,-Wdeclaration-after-statement,)

# disable pointer signed / unsigned warnings in gcc 4.0
KBUILD_CFLAGS += $(call cc-disable-warning, pointer-sign)

# disable invalid "can't wrap" optimizations for signed / pointers
KBUILD_CFLAGS	+= $(call cc-option,-fno-strict-overflow)

# conserve stack if available
KBUILD_CFLAGS   += $(call cc-option,-fconserve-stack)

# disallow errors like 'EXPORT_GPL(foo);' with missing header
KBUILD_CFLAGS   += $(call cc-option,-Werror=implicit-int)

# require functions to have arguments in prototypes, not empty 'int foo()'
KBUILD_CFLAGS   += $(call cc-option,-Werror=strict-prototypes)

# Prohibit date/time macros, which would make the build non-deterministic
KBUILD_CFLAGS   += $(call cc-option,-Werror=date-time)

# enforce correct pointer usage
KBUILD_CFLAGS   += $(call cc-option,-Werror=incompatible-pointer-types)

# use the deterministic mode of AR if available
KBUILD_ARFLAGS := $(call ar-option,D)

# check for 'asm goto'
ifeq ($(shell $(CONFIG_SHELL) $(srctree)/scripts/gcc-goto.sh $(CC)), y)
KBUILD_CFLAGS += -DCC_HAVE_ASM_GOTO
KBUILD_AFLAGS += -DCC_HAVE_ASM_GOTO
endif

include scripts/Makefile.extrawarn

# Add any arch overrides and user supplied CPPFLAGS, AFLAGS and CFLAGS
# as the last assignments
KBUILD_CPPFLAGS += $(ARCH_CPPFLAGS) $(KCPPFLAGS)
KBUILD_AFLAGS   += $(ARCH_AFLAGS)   $(KAFLAGS)
KBUILD_CFLAGS   += $(ARCH_CFLAGS)   $(KCFLAGS)

# Default kernel image to build when no specific target is given.
# KBUILD_IMAGE may be overruled on the command line or set in the environment
# Also any assignments in arch/$(ARCH)/Makefile take precedence over
# this default value
export KBUILD_IMAGE ?= vmImage

# INSTALL_PATH specifies where to place the updated kernel and system map
# images. Default is /boot, but you can set it to other values
export INSTALL_PATH ?= /boot

# INSTALL_MOD_PATH specifies a prefix to MODLIB for module directory
# relocations required by build roots.  This is not defined in the
# makefile but the argument can be passed to make if needed.
MODLIB	= $(INSTALL_MOD_PATH)/lib/modules/$(KERNELRELEASE)
export MODLIB

ifeq ($(KBUILD_EXTMOD),)
# Objects that will be linked into final vmImage
# These variables are initialized in arch Makefile
init-y		:= init/
core-y		+= kernel/ mm/ fs/ components/
drivers-y	+= drivers/
net-y		:= net/
libs-y		+= lib/

vmImage-dirs	:= $(patsubst %/,%,$(filter %/, $(init-y) $(core-y) $(drivers-y) $(net-y) $(libs-y)))
init-y		:= $(patsubst %/, %/built-in.o, $(init-y))
core-y		:= $(patsubst %/, %/built-in.o, $(core-y))
drivers-y	:= $(patsubst %/, %/built-in.o, $(drivers-y))
net-y		:= $(patsubst %/, %/built-in.o, $(net-y))
libs-y		:= $(patsubst %/, %/built-in.o, $(libs-y))

# Externally visible to link-vmImage.sh
export KBUILD_VMIMAGE_INIT := $(head-y) $(init-y)
export KBUILD_VMIMAGE_MAIN := $(core-y) $(libs-y) $(drivers-y) $(net-y)
export KBUILD_LDS          := arch/$(SRCARCH)/kernel/vmImage.lds
export LDFLAGS_vmImage

vmImage-deps := $(KBUILD_LDS) $(KBUILD_VMIMAGE_INIT) $(KBUILD_VMIMAGE_MAIN)

# Final link of vmImage
quiet_cmd_link-vmImage = LINK    $@
cmd_link-vmImage = $(CONFIG_SHELL) $< $(LD) $(LDFLAGS) $(LDFLAGS_vmImage)

vmImage: scripts/link-vmImage.sh $(vmImage-deps) FORCE
	+$(call if_changed,link-vmImage)

# The actual objects are generated when descending,
# make sure no implicit rule kicks in
$(sort $(vmImage-deps)): $(vmImage-dirs) ;

PHONY += $(vmImage-dirs)
$(vmImage-dirs): prepare scripts
	$(Q)$(MAKE) $(build)=$@

define filechk_kernel.release
	echo "$(KERNELVERSION)$$($(CONFIG_SHELL) $(srctree)/scripts/setlocalversion $(srctree))"
endef

# Store (new) KERNELRELEASE string in include/config/kernel.release
include/config/kernel.release: include/config/auto.conf FORCE
	$(call filechk,kernel.release)

#
# Things we need to do before we recursively start building the kernel
# or the modules are listed in "prepare".
# A multi level approach is used. prepareN is processed before prepareN-1.
# version.h and scripts_basic is processed / created.
#

# Listed in dependency order
PHONY += prepare prepare1 prepare2 prepare3

# prepare3 is used to check if we are building in a separate output directory,
# and if so do:
# 1) Check that make has not been executed in the kernel src $(srctree)
prepare3: include/config/kernel.release
ifneq ($(KBUILD_SRC),)
	@$(kecho) '  Using $(srctree) as source for kernel'
	$(Q)if [ -f $(srctree)/.config -o -d $(srctree)/include/config ]; then \
		echo >&2 "  $(srctree) is not clean, please run 'make mrproper'"; \
		echo >&2 "  in the '$(srctree)' directory.";\
		/bin/false; \
	fi;
endif

# prepare2 creates a makefile if using a separate output directory.
# From this point forward, .config has been reprocessed, so any rules
# that need to depend on updated CONFIG_* values can be checked here.
prepare2: prepare3 outputmakefile

prepare1: prepare2 $(version_h) include/generated/utsrelease.h \
                   include/config/auto.conf
	$(Q)test -e include/generated/autoksyms.h || \
	    touch   include/generated/autoksyms.h

# All the preparing..
# Top level Kbuild will be included here and it will build things prior
# to any makefile is invoked.
prepare: archprepare prepare1 scripts_basic
	$(Q)$(MAKE) $(build)=.

# Generate some files
# ---------------------------------------------------------------------------

# KERNELRELEASE can change from a few different places, meaning version.h
# needs to be updated, so this check is forced on all builds

uts_len := 64
define filechk_utsrelease.h
	if [ `echo -n "$(KERNELRELEASE)" | wc -c ` -gt $(uts_len) ]; then \
	  echo '"$(KERNELRELEASE)" exceeds $(uts_len) characters' >&2;    \
	  exit 1;                                                         \
	fi;                                                               \
	(echo \#define UTS_RELEASE \"$(KERNELRELEASE)\";)
endef

define filechk_version.h
	(echo \#define LEGO_VERSION_CODE $(shell                         \
	expr $(VERSION) \* 65536 + 0$(PATCHLEVEL) \* 256 + 0$(SUBLEVEL)); \
	echo '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))';)
endef

$(version_h): $(srctree)/Makefile FORCE
	$(call filechk,version.h)

include/generated/utsrelease.h: include/config/kernel.release FORCE
	$(call filechk,utsrelease.h)

# Detect inclusion cycles in header files
PHONY += headerdep
headerdep:
	$(Q)find $(srctree)/include/ -name '*.h' | xargs --max-args 1 \
	$(srctree)/scripts/headerdep.pl -I$(srctree)/include

# ---------------------------------------------------------------------------
# Modules
ifdef CONFIG_MODULES
# By default, build modules as well
all: modules
$(error not implemented now)
else
# ---------------------------------------------------------------------------
# Modules not configured
PHONY += modules modules_install
modules modules_install:
	@echo >&2
	@echo >&2 "The present kernel configuration has modules disabled."
	@echo >&2 "Type 'make config' and enable loadable module support."
	@echo >&2 "Then build a kernel with module support enabled."
	@echo >&2
	@exit 1
endif # CONFIG_MODULES

###
# Cleaning is done on three levels.
# make clean     Delete most generated files
#                Leave enough to build external modules
# make mrproper  Delete the current configuration, and all generated files
# make distclean Remove editor backup files, patch leftover files and the like

MRPROPER_DIRS	+= include/config include/generated arch/*/include/generated
MRPROPER_DIRS	+= test-output
MRPROPER_FILES	+= .config .config.old tags TAGS tags-e
MRPROPER_FILES  += output output_ttyS0 output_ttyS1

clean-dirs	:= $(addprefix _clean_, . $(vmImage-dirs) scripts/)

PHONY += $(clean-dirs) clean archclean vmImageclean
$(clean-dirs):
	$(Q)$(MAKE) $(clean)=$(patsubst _clean_%,%,$@)

vmImageclean:
	$(Q)$(CONFIG_SHELL) $(srctree)/scripts/link-vmImage.sh clean

clean: $(clean-dirs) archclean vmImageclean
	@find $(srctree) \
		\( -name '.*.cmd' -o -name '*.o' \) \
		-type f -print | xargs rm -f


PHONY += mrproper
mrproper: clean
	$(Q)rm -rf $(MRPROPER_DIRS)
	$(Q)rm -f $(MRPROPER_FILES)

export RCS_FIND_IGNORE := \( -name SCCS -o -name BitKeeper -o -name .svn -o    \
			  -name CVS -o -name .pc -o -name .hg -o -name .git \) \
			  -prune -o
PHONY += distclean
distclean: mrproper
	@find $(srctree) $(RCS_FIND_IGNORE) \
		\( -name '*.orig' -o -name '*.rej' -o -name '*~' \
		-o -name '*.bak' -o -name '#*#' -o -name '.*.orig' \
		-o -name '.*.rej' -o -name '*%'  -o -name 'core' \) \
		-type f -print | xargs rm -f

# Brief documentation of the typical targets used
# ---------------------------------------------------------------------------

boards := $(wildcard $(srctree)/arch/$(SRCARCH)/configs/*_defconfig)
boards := $(sort $(notdir $(boards)))
board-dirs := $(dir $(wildcard $(srctree)/arch/$(SRCARCH)/configs/*/*_defconfig))
board-dirs := $(sort $(notdir $(board-dirs:/=)))

PHONY += help
help:
	@echo  'Cleaning targets:'
	@echo  '  clean		  - Remove most generated files but keep the config and'
	@echo  '                    enough build support to build external modules'
	@echo  '  mrproper	  - Remove all generated files + config + various backup files'
	@echo  '  distclean	  - mrproper + remove editor backup and patch files'
	@echo  ''
	@echo  'Configuration targets:'
	@$(MAKE) -f $(srctree)/scripts/kconfig/Makefile help
	@echo  ''
	@echo  'Other generic targets:'
	@echo  '  all		  - Build all targets marked with [*]'
	@echo  '* vmImage	  - Build the bare kernel'
	@echo  '  dir/            - Build all files in dir and below'
	@echo  '  dir/file.[ois]  - Build specified target only'
	@echo  '  dir/file.lst    - Build specified mixed source/assembly target only'
	@echo  '                    (requires a recent binutils and recent build (System.map))'
	@echo  '  tags/TAGS	  - Generate tags file for editors'
	@echo  '  kernelrelease	  - Output the release version string (use with make -s)'
	@echo  '  kernelversion	  - Output the version stored in Makefile (use with make -s)'
	@echo  '  image_name	  - Output the image name (use with make -s)'
	@echo  ''
	@echo  'Static analysers'
	@echo  '  versioncheck    - Sanity check on version.h usage'
	@echo  '  includecheck    - Check for duplicate included header files'
	@echo  '  headerdep       - Detect inclusion cycles in headers'
	@echo  ''
	@echo  'Architecture specific targets ($(SRCARCH)):'
	@$(if $(archhelp),$(archhelp),\
		echo '  No architecture specific help defined for $(SRCARCH)')
	@echo  ''
	@$(if $(boards), \
		$(foreach b, $(boards), \
		printf "  %-24s - Build for %s\\n" $(b) $(subst _defconfig,,$(b));) \
		echo '')
	@$(if $(board-dirs), \
		$(foreach b, $(board-dirs), \
		printf "  %-16s - Show %s-specific targets\\n" help-$(b) $(b);) \
		printf "  %-16s - Show all of the above\\n" help-boards; \
		echo '')

	@echo  '  make V=0|1 [targets] 0 => quiet build (default), 1 => verbose build'
	@echo  '  make V=2   [targets] 2 => give reason for rebuild of target'
	@echo  '  make O=dir [targets] Locate all output files in "dir", including .config'
	@echo  '		1: warnings which may be relevant and do not occur too often'
	@echo  '		2: warnings which occur quite often but may still be relevant'
	@echo  '		3: more obscure warnings, can most likely be ignored'
	@echo  '		Multiple levels can be combined with W=12 or W=123'
	@echo  ''
	@echo  'Execute "make" or "make all" to build all targets marked with [*] '
	@echo  'For further info contact Wuklab (http://wuklab.io)'

else # KBUILD_EXTMOD

###
# External module support.
# When building external modules the kernel used as basis is considered
# read-only, and no consistency checks are made and the make
# system is not used on the basis kernel. If updates are required
# in the basis kernel ordinary make commands (without M=...) must
# be used.
#
# The following are the only valid targets when building external
# modules.
# make M=dir clean     Delete all automatically generated files
# make M=dir modules   Make all modules in specified dir
# make M=dir	       Same as 'make M=dir modules'
# make M=dir modules_install
#                      Install the modules built in the module directory
#                      Assumes install directory is already created
$(error not implemented now)
endif # KBUILD_EXTMOD

# Generate tags for editors
# ---------------------------------------------------------------------------
quiet_cmd_tags = GEN     $@
      cmd_tags = $(CONFIG_SHELL) $(srctree)/scripts/tags.sh $@

tags TAGS: FORCE
	$(call cmd,tags)

# Scripts to check various things for consistency
# ---------------------------------------------------------------------------
PHONY += includecheck versioncheck coccicheck namespacecheck export_report

includecheck:
	find $(srctree)/* $(RCS_FIND_IGNORE) \
		-name '*.[hcS]' -type f -print | sort \
		| xargs $(PERL) -w $(srctree)/scripts/checkincludes.pl

versioncheck:
	find $(srctree)/* $(RCS_FIND_IGNORE) \
		-name '*.[hcS]' -type f -print | sort \
		| xargs $(PERL) -w $(srctree)/scripts/checkversion.pl
endif #ifeq ($(config-targets),1)
endif #ifeq ($(mixed-targets),1)

PHONY += kernelrelease kernelversion image_name

kernelrelease:
	@echo "$(KERNELVERSION)$$($(CONFIG_SHELL) $(srctree)/scripts/setlocalversion $(srctree))"

kernelversion:
	@echo $(KERNELVERSION)

image_name:
	@echo $(KBUILD_IMAGE)

# Single targets
# ---------------------------------------------------------------------------
# Single targets are compatible with:
# - build with mixed source and output
# - build with separate output dir 'make O=...'
# - external modules
#
#  target-dir => where to store outputfile
#  build-dir  => directory in kernel source tree to use

ifeq ($(KBUILD_EXTMOD),)
        build-dir  = $(patsubst %/,%,$(dir $@))
        target-dir = $(dir $@)
else
        zap-slash=$(filter-out .,$(patsubst %/,%,$(dir $@)))
        build-dir  = $(KBUILD_EXTMOD)$(if $(zap-slash),/$(zap-slash))
        target-dir = $(if $(KBUILD_EXTMOD),$(dir $<),$(dir $@))
endif

%.s: %.c prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)
%.i: %.c prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)
%.o: %.c prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)
%.lst: %.c prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)
%.s: %.S prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)
%.o: %.S prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)
%.symtypes: %.c prepare scripts FORCE
	$(Q)$(MAKE) $(build)=$(build-dir) $(target-dir)$(notdir $@)

# read all saved command lines
targets := $(wildcard $(sort $(targets)))
cmd_files := $(wildcard .*.cmd $(foreach f,$(targets),$(dir $(f)).$(notdir $(f)).cmd))

ifneq ($(cmd_files),)
  $(cmd_files): ;	# Do not try to update included dependency files
  include $(cmd_files)
endif

endif # skip-makefile

PHONY += FORCE
FORCE:

# Declare the contents of the .PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)
