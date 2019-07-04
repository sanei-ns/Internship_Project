#!/usr/bin/env bash

# Plugin name
PLUGINNAME=findexer

# Plugin execution order, as 3-digit decimal
PLUGINORDER=961

# Add necessary libraries here using -l option
CFLAGS="-Wundef"

# Also build fextractor
t2_prebuild() {
    make -C fextractor
}

# Also clean fextractor and doc
t2_clean() {
    make clean -C fextractor
    make clean -C doc
    rm -rf scripts/cipaddress/build
}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
