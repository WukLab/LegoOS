#
# Processor mmap range management
#

obj-y := syscall.o
obj-$(CONFIG_DISTRIBUTED_VMA_PROCESSOR) += distvm.o 

distvm-y := dist_mmap.o
distvm-$(CONFIG_VMA_PROCESSOR_UNITTEST) += dist_mmap_test.o
