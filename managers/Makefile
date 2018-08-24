#
# Lego Managers
# Keep it complex then hide it?
# Keep it simple stupid?
#

obj-$(CONFIG_COMP_PROCESSOR)	:= processor/
obj-$(CONFIG_COMP_MEMORY)	+= memory/

# Library tools used by both processor and memory managers
obj-y				+= lib/

obj-y				+= common.o
obj-y				+= pin.o
obj-$(CONFIG_SOFT_WATCHDOG)	+= watchdog.o
