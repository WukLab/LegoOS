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
obj-$(CONFIG_PROFILING_BOOT_RPC) += rpc_profile.o

obj-$(CONFIG_VNODE) += vnode.o
obj-$(CONFIG_REPLICATION_MEMORY) += replication.o
obj-$(CONFIG_CHECKPOINT) += checkpoint/
obj-$(CONFIG_STRACE) += strace/

#
# Extended Processor Cache Subsystem
#
obj-y += pcache/
obj-$(CONFIG_PCACHE_ZEROFILL_NOTIFY_MEMORY) += zerofill_notify.o
