#!/usr/bin/env bash

# Plugin name
PLUGINNAME=nDPI

# Plugin execution order, as 3-digit decimal
PLUGINORDER=112

# Add necessary libraries here using -l option
CFLAGS="-DNDPI_LIB_COMPILATION"

t2_clean() {
    ./clean.sh
    # Also clean doc
    make mrproper -C prototex
    make clean -C doc
}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
