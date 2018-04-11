#
# Makefile for Lego processor-component manager
#

obj-y := core.o
obj-y += fork.o
obj-y += exec.o
obj-y += pgtable.o
obj-y += wait.o
obj-y += prctl.o
obj-y += mmap/
obj-y += fs/
obj-y += monitor/

obj-$(CONFIG_CHECKPOINT) += checkpoint/
obj-$(CONFIG_STRACE) += strace/

#
# Extended Processor Cache Subsystem
#
obj-y += pcache/
obj-$(CONFIG_PCACHE_ZEROFILL_NOTIFY_MEMORY) += zerofill_notify.o
