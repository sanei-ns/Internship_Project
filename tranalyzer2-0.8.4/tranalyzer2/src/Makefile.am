bin_PROGRAMS = tranalyzer

tranalyzer_CFLAGS = \
	-D_GNU_SOURCE=1 \
	-D_REENTRANT

tranalyzer_LDFLAGS = \
	$(LTLDFLAGS)

tranalyzer_SOURCES = \
	binaryValue.c \
	hash/city.c \
	hash/fasthash.c \
	hash/hashlittle.c \
	hash/murmur3.c \
	hash/xxhash.c \
	hashTable.c \
	hdrDesc.c \
	ioBuffer.c \
	loadPlugins.c \
	main.c \
	outputBuffer.c \
	packetCapture.c \
	proto/ayiya.c \
	proto/capwap.c \
	proto/geneve.c \
	proto/gtp.c \
	proto/ieee80211.c \
	proto/lwapp.c \
	proto/vlan.c \
	proto/vxlan.c \
	../../utils/bsdstring.c \
	../../utils/fsutils.c \
	../../utils/memdebug.c \
	../../utils/t2log.c \
	../../utils/t2utils.c

if APPLE
tranalyzer_SOURCES += ../../utils/memrchr.c
endif
