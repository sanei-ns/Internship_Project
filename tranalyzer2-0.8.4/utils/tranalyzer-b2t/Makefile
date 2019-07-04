CC             = gcc
RM             = rm -f
CFLAGS_DEFAULT = -pipe -Wall -Wextra -Wundef -std=gnu99 -D_GNU_SOURCE -MMD -MP \
                 -DUSE_ZLIB=2 -I".." -I"../../tranalyzer2/src/"
CFLAGS         = $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   = $(CFLAGS_DEFAULT) -O0 -g3 -ggdb
LDFLAGS        = -lm -lz
SRC            = tranalyzer-b2t.c \
                 ../../tranalyzer2/src/binaryValue.c \
                 ../bin2txt.c \
                 ../gz2txt.c
OBJS           = $(SRC:.c=.o)
DEPS           = $(OBJS:.o=.d)

EXEC           = tranalyzer-b2t

.PHONY: all debug

all: $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

-include $(DEPS)

.PHONY: clean distclean

clean:
	$(RM) $(OBJS) $(DEPS)

distclean: clean
	$(RM) $(EXEC)
