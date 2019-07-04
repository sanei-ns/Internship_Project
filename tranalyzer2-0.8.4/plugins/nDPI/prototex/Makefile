CC      = gcc
CFLAGS  = -Wall -Wextra -Wundef -std=gnu99 -I../src/nDPI/src/include
LDFLAGS =
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
TARGET  = prototex
NDPIDIR = ../src/nDPI
NDPILIB = $(NDPIDIR)/src/lib/.libs/libndpi.a

.PHONY: all release debug clean mrproper

all: release

release: CFLAGS += -O3
release: LDFLAGS += -s
release: $(TARGET)

debug: CFLAGS +=  -O0 -g3 -ggdb
debug: $(TARGET)

$(TARGET): $(OBJECTS)
ifeq ($(wildcard $(NDPILIB)),)
	$(error Please run ./autogen.sh in the parent directory first to build the nDPI library)
endif
	$(CC) $(CFLAGS) -o $@ $^ $(NDPILIB)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) *.o

mrproper: clean
	$(RM) $(TARGET)
