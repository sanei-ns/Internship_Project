CC             = gcc
RM             = rm -f
CFLAGS_DEFAULT = -pipe -Wall -Wextra -std=gnu99 -D_GNU_SOURCE -MMD -MP \
                 -I../../../utils/ -I../src -I../../../tranalyzer2/src
CFLAGS         = $(CFLAGS_DEFAULT) -O3
CFLAGS_DEBUG   = $(CFLAGS_DEFAULT) -O0 -g3 -ggdb
#LDFLAGS        = -lm

# IPv4 utilities
#SRC4           = $(wildcard *4.c)
SRC4           = ext4.c nett4.c vect4.c sbm4.c
EXEC4          = $(SRC4:.c=)
OBJS4          = $(SRC4:.c=.o)
DEPS4          = $(OBJS4:.o=.d)

# IPv6 utilities
#SRC6           = $(wildcard *6.c)
SRC6           = ext6.c nett6.c vect6.c sbm6.c
EXEC6          = $(SRC6:.c=)
OBJS6          = $(SRC6:.c=.o)
DEPS6          = $(OBJS6:.o=.d)

EXEC           = $(EXEC4) $(EXEC6)
SRC            = $(wildcard *.c)
OBJS           = $(SRC:.c=.o)
DEPS           = $(OBJS:.o=.d)

.PHONY: all debug utils_v4 utils_v6

all: utils_v4 utils_v6

utils_v4: $(EXEC4)

utils_v6: $(EXEC6)

debug: CFLAGS=$(CFLAGS_DEBUG)
debug: all

#%: %.o
#	$(CC) $(LDFLAGS) $^ -o $@
#
#%.o: %.c
#	$(CC) $(CFLAGS) -c $< -o $@

sbm4:
	$(CC) $(CFLAGS) sbm4.c -o sbm4

ext4:
	$(CC) $(CFLAGS) ext4.c -o ext4

nett4:
	$(CC) $(CFLAGS) nett4.c -o nett4

vect4:
	$(CC) $(CFLAGS) vect4.c -o vect4

sbm6:
	$(CC) $(CFLAGS) sbm6.c -o sbm6

ext6:
	$(CC) $(CFLAGS) ext6.c -o ext6

nett6:
	$(CC) $(CFLAGS) nett6.c -o nett6

vect6:
	$(CC) $(CFLAGS) vect6.c -o vect6

upwho4:
	$(CC) $(CFLAGS) upwho4.c ../src/subnetHL4.c ../../../utils/t2utils.c -o upwho4

upwho6:
	$(CC) $(CFLAGS) upwho6.c ../src/subnetHL6.c ../../../utils/t2utils.c -o upwho6

rng6:
	$(CC) $(CFLAGS) rng6.c -o rng6

-include $(DEPS)

.PHONY: clean clean_v4 clean_v6 distclean distclean_v4 distclean_v6

clean_v4:
	$(RM) $(OBJS4) $(DEPS4)

clean_v6:
	$(RM) $(OBJS6) $(DEPS6)

clean:
	$(RM) $(OBJS) $(DEPS)

distclean_v4:
	$(RM) $(EXEC4)

distclean_v6:
	$(RM) $(EXEC6)

distclean: clean
	$(RM) $(EXEC)
