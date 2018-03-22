#
# Process Virtual Memroy Subsystem in Lego memory-component
#

obj-y := mmap.o
obj-y += fault.o
obj-y += pgtable.o
obj-y += uaccess.o
obj-y += gup.o
obj-y += debug.o
obj-$(CONFIG_DISTRIBUTED_VMA_MEMORY) += distvm.o

distvm-y := dist_mmap.o
distvm-y += dist_mmap_dump.o
distvm-$(CONFIG_VMA_MEMORY_UNITTEST) += dist_mmap_test.o
