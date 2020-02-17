#
# Lego Memory Component
#

obj-y := core.o
obj-y += task.o
obj-y += handle_fork.o
obj-y += handle_execve.o
obj-y += handle_mmap.o
obj-y += handle_file.o
obj-y += handle_checkpoint.o
obj-y += file_ops.o
obj-y += missing_syscalls.o
obj-y += m2s_read_write.o
obj-y += stat.o
obj-y += test.o

# Pcache
obj-y += handle_pcache/

# Replication
obj-y += replica/

# Virtual Memory Subsystem
obj-y += vm/

# Loader
obj-y += loader/

# Lego Page Cache
obj-$(CONFIG_MEM_PAGE_CACHE) += pgcache/

obj-y += ramfs/

# Monitor
obj-y += monitor/
