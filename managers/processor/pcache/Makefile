#
# Processor DRAM Cache Subsystem
#

obj-y := fault.o
obj-y += init.o
obj-y += alloc.o
obj-y += clflush.o
obj-y += rmap.o
obj-y += debug.o
obj-y += evict.o
obj-y += stat.o
obj-y += syscall.o
obj-y += mmap.o
obj-$(CONFIG_PCACHE_PREFETCH) += prefetch.o
obj-$(CONFIG_PCACHE_EVICTION_VICTIM) += victim.o victim_flush.o

#
# Eviction Algorithm
#
obj-$(CONFIG_PCACHE_EVICT_LRU) += evict_lru.o
obj-$(CONFIG_PCACHE_EVICT_FIFO) += evict_fifo.o
obj-$(CONFIG_PCACHE_EVICT_RANDOM) += evict_random.o

# Sweep threads for certain eviction algorithms
obj-$(CONFIG_PCACHE_EVICT_GENERIC_SWEEP) += evict_sweep.o
