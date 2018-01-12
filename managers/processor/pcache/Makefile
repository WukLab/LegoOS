#
# Processor DRAM Cache Subsystem
#

obj-y := fault.o
obj-y += init.o
obj-y += alloc.o
obj-y += clflush.o
obj-y += rmap.o
obj-y += debug.o
obj-y += eviction.o
obj-y += stat.o
obj-y += syscall.o
obj-$(CONFIG_PCACHE_PREFETCH) += prefetch.o
obj-$(CONFIG_PCACHE_EVICTION_VICTIM) += victim.o victim_flush.o

# Sweep threads for certain eviction algorithms
obj-$(CONFIG_PCACHE_EVICT_COMMON_SWEEP) += evict_sweep.o
