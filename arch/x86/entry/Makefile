#
# Kernel Entry Points
#

obj-y := entry_$(BITS).o syscall_$(BITS).o
obj-y += common.o
obj-y += vsyscall/

obj-$(CONFIG_IA32_EMULATION) += entry_64_compat.o
