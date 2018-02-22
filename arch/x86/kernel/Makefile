extra-y += vmImage.lds

obj-y := head_64.o head64.o
obj-y += process.o
obj-y += dumpstack.o
obj-y += setup.o
obj-y += e820.o
obj-y += pci-dma.o
obj-y += pci-nommu.o
obj-y += cpu/

obj-y += percpu.o
obj-y += smp.o smpboot.o
obj-y += time.o rtc.o
obj-y += hpet.o i8253.o tsc.o
obj-y += traps.o irq.o irqinit.o i8259.o
obj-y += acpi/ apic/
obj-y += fpu/
obj-y += alternative.o
obj-y += signal.o
obj-y += ptrace.o

# Enable CONFIG_FRAME_POINTER to get precise kernel stack dumpinfo
ifdef CONFIG_FRAME_POINTER
obj-y += unwind_frame.o
else
obj-y += unwind_guess.o
endif
