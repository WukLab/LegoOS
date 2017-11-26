CFLAGS := -static

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

srctree := ../
objtree := ../
SRCARCH := x86
LEGO_INCLUDE	:= -I$(srctree)/arch/$(SRCARCH)/include \
                   -I$(objtree)/arch/$(SRCARCH)/include/generated \
                   -I$(objtree)/arch/$(SRCARCH)/include/generated/uapi \
		   -I$(objtree)/include

all: $(OBJS)

clean:
	rm -f *.o

%.o: %.c includeme.h
	gcc -g -o $@ $(CFLAGS) $(LEGO_INCLUDE) $< -lm -pthread
