CC             = gcc
RM             = rm -f
CFLAGS_DEFAULT = -pipe -Wall -Wextra -std=gnu99 -D_GNU_SOURCE -MMD -MP  \
                 -I ../src/ -I ../../../utils/ -I ../../../tranalyzer2/src/
CFLAGS         = $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   = $(CFLAGS_DEFAULT) -O0 -g3 -ggdb
#LDFLAGS        =

EXEC           = mbm
SRC            = $(wildcard *.c)
OBJS           = $(SRC:.c=.o)
DEPS           = $(OBJS:.o=.d)

.PHONY: all debug

all: $(EXEC)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

-include $(DEPS)

.PHONY: clean distclean

clean:
	$(RM) $(OBJS) $(DEPS)

distclean: clean
	$(RM) $(EXEC)
