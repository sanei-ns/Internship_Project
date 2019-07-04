CC             = gcc
RM             = rm -f
CFLAGS_DEFAULT = -pipe -Wall -Wextra -Wundef -std=gnu99 -D_GNU_SOURCE -MMD -MP \
                 -I../../../tranalyzer2/src/ -I../../../utils -I../src
CFLAGS         = $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   = $(CFLAGS_DEFAULT) -O0 -g3 -ggdb
LDFLAGS        = -lm
SRC            = bsHL4.c ../src/subnetHL4.c ../../../utils/t2utils.c
OBJS           = $(SRC:.c=.o)
DEPS           = $(OBJS:.o=.d)

EXEC           = bsHL4

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
