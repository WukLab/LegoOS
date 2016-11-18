extra-y += vmImage.lds

obj-y := head_64.o
obj-y += head64.o
obj-y += entry.o
obj-y += process.o
obj-y += dumpstack.o
obj-y += setup.o
obj-y += traps.o
obj-y += e820.o
obj-y += cpu.o cpu_intel.o
obj-y += smp.o
obj-y += ipi.o
obj-y += apic.o io_apic.o

#
# Always a good idea to enable CONFIG_FRAME_POINTER
#
ifdef CONFIG_FRAME_POINTER
obj-y += unwind_frame.o
else
obj-y += unwind_guess.o
endif
