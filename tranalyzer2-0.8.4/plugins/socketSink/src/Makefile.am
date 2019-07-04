lib_LTLIBRARIES = libsocketSink.la

libsocketSink_la_SOURCES = \
	socketSink.c \
	../../../utils/bin2txt.c \
	../../../utils/chksum.c

if GZ_COMPRESS_SET
libsocketSink_la_SOURCES += ../../../utils/gz2txt.c
endif

if APPLE
libsocketSink_la_SOURCES += ../../../utils/open_memstream.c
endif
