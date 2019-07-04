lib_LTLIBRARIES = libregex_pcre.la

libregex_pcre_la_SOURCES = \
	regex_pcre.c \
	regfile_pcre.c

libregex_pcre_la_CFLAGS = \
	-I ../../tcpFlags/src

if APPLE
libregex_pcre_la_CFLAGS += -I/usr/local/opt/pcre/include
libregex_pcre_la_LDFLAGS = -L/usr/local/opt/pcre/lib
endif
