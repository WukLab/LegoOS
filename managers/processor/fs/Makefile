#
# Filesystem Interfaces in Lego Processor Manager
#

obj-y := read_write.o
obj-y += open.o
obj-y += stat.o
obj-y += fcntl.o
obj-y += ioctl.o
obj-y += stdio.o
obj-y += truncate.o
obj-y += namei.o
obj-$(CONFIG_MEM_PAGE_CACHE) += file_size.o
obj-y += statfs.o
obj-y += pipe.o
obj-y += lseek.o
obj-y += default_f_ops.o
obj-y += drop_cache.o

#
# To maintain compability with linux
#
obj-y += seq_file.o
obj-y += proc/
obj-y += sys/
obj-y += dev/
