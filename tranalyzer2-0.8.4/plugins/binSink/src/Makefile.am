lib_LTLIBRARIES = libbinSink.la

libbinSink_la_SOURCES = \
	binSink.c \
	../../../utils/bin2txt.c \
	../../../utils/chksum.c

if GZ_COMPRESS_SET
libbinSink_la_SOURCES += ../../../utils/gz2txt.c
endif
