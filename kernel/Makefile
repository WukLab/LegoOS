#
# Makefile for Lego core functionalities
#

obj-y := panic.o
obj-y += printk.o
obj-y += kallsyms.o
obj-y += cpu.o
obj-y += resource.o
obj-y += smp.o
obj-y += param.o
obj-y += time/
obj-y += irq/
obj-y += sched/
obj-y += locking/
obj-y += fork.o
obj-y += pid.o
obj-y += exit.o
obj-y += mutex.o
obj-y += sys.o
obj-y += kthread.o
obj-y += extable.o
obj-y += signal.o
obj-y += coredump.o
obj-y += madvise.o
obj-y += stop_machine.o
obj-y += smpboot.o
obj-y += itimer.o

obj-$(CONFIG_FUTEX) += futex.o
obj-$(CONFIG_WORK_QUEUE) += workqueue.o
obj-$(CONFIG_PROFILING) += profile/
