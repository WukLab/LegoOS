#
# LegoOS Physical Memory Managment
#

obj-y := debug.o
obj-y += memory.o
obj-y += init-mm.o
obj-y += vmalloc.o
obj-y += dmapool.o
obj-y += memblock.o
obj-y += page_alloc.o
obj-y += early_ioremap.o
obj-y += percpu.o
obj-y += maccess.o
obj-y += mbind.o
obj-y += vmstat.o

obj-y += slab_common.o
obj-$(CONFIG_SLOB) += slob.o

obj-$(CONFIG_SPARSEMEM) += sparse.o
obj-$(CONFIG_SPARSEMEM_VMEMMAP) += sparse-vmemmap.o
