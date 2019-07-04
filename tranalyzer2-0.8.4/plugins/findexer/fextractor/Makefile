CC      = gcc
CFLAGS  = -Wall -Wextra -Wundef -std=gnu99 -I../../../utils
LDFLAGS =
SOURCES = $(wildcard *.c) ../../../utils/heap.c
OBJECTS = $(SOURCES:.c=.o)
TARGET  = fextractor

.PHONY: all release debug clean mrproper

all: clean release

release: CFLAGS += -O3
release: LDFLAGS += -s
release: $(TARGET)

debug: CFLAGS +=  -O0 -g3 -ggdb
debug: clean $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

install:
	install $(TARGET) /usr/bin/

clean:
	$(RM) $(OBJECTS)

mrproper: clean
	$(RM) $(TARGET)
