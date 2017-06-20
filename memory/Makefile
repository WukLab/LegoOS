#
# LegoOS Memory Component
#

#obj-$(CONFIG_MEMCOMPONENT) := memory.o

memory.y	:= mem.o
memory.y	+= mem_local_alloc.o
memory.y	+= mmap.o
#mem.o += mem_global_alloc.o

obj-$(CONFIG_MEMCOMPONENT) := mem.o mem_local_alloc.o mmap.o
