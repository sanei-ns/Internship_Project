#!/usr/bin/env bash

# Plugin name
PLUGINNAME=socketSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=910

GZ_COMPRESS=$(perl -nle 'print $1 if /^#define\s+GZ_COMPRESS\s+(\d+).*$/' src/socketSink.h)
[ -z "$GZ_COMPRESS" ] && GZ_COMPRESS=0

if [ $GZ_COMPRESS -eq 1 ]; then
    # Add necessary libraries here using -l option
    LIBS="-lz"

    # Dependencies (use this to report missing deps)
    DEPS="zlib"
fi

CFLAGS="-DUSE_ZLIB=$GZ_COMPRESS"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
