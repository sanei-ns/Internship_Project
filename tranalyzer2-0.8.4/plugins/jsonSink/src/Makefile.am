lib_LTLIBRARIES = libjsonSink.la

libjsonSink_la_SOURCES = \
	jsonSink.c \
	../../../utils/bin2txt.c

if GZ_COMPRESS_SET
libjsonSink_la_SOURCES += ../../../utils/gz2txt.c
endif
