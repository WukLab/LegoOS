obj-y := piggy.o
obj-y += core.o

#
# Add dependency, so it can compile if .config changes
#

$(CONFIG_RAMFS_OBJECT_FILE):

$(obj)/piggy.o: $(CONFIG_RAMFS_OBJECT_FILE)
