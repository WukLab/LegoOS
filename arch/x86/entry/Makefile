#
# Kernel Entry Points
#

obj-y := entry_$(BITS).o syscall_$(BITS).o
obj-y += common.o

obj-$(CONFIG_IA32_EMULATION) += entry_64_compat.o

obj-$(CONFIG_TRACE_SYSCALL) += strace.o
