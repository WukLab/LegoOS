extra-y += vmImage.lds

obj-y := head_64.o head64.o
obj-y += entry.o
obj-y += process.o
obj-y += dumpstack.o
obj-y += setup.o
obj-y += traps.o
obj-y += e820.o

ifdef CONFIG_FRAME_POINTER
obj-y += unwind_frame.o
else
obj-y += unwind_guess.o
endif
