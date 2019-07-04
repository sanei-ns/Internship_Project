SUBDIRS = nDPI

lib_LTLIBRARIES = libnDPI.la

libnDPI_la_SOURCES = \
	nDPI.c

libnDPI_la_CFLAGS = \
	-InDPI/src/include

#libnDPI_la_LDFLAGS = \
#	-Wl,--whole-archive,nDPI/src/lib/libndpi.a,--no-whole-archive

libnDPI_la_LIBADD = \
	nDPI/src/lib/libndpi.la
