.PHONY: clean

CFLAGS  := -Wall -g
LD      := gcc
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread -ldl
DEPS = pingpong.h

APPS    := rc-pingpong

all: ${APPS}

rc-pingpong: rc_pingpong.o pingpong.o
	${LD} -o $@ $^ ${LDLIBS} $(DEPS)

clean:
	rm -f *.o ${APPS}

