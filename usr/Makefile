CFLAGS := -static

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

clean:
	rm -f *.o

%.o: %.c
	gcc -g -o $@ $(CFLAGS) $< -lm -pthread
