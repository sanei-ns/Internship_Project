#!/usr/bin/env bash

# Plugin name
PLUGINNAME=macRecorder

# Plugin execution order, as 3-digit decimal
PLUGINORDER=110

MACLBL=$(perl -nle 'print $1 if /^#define\s+MR_MACLBL\s+(\d+).*$/' src/macRecorder.h)

t2_clean() {
    make -C utils distclean
    rm -f maclbl.bin
}

# prepare mac label file
t2_preinst() {
    # mac file
    if [ $MACLBL -gt 0 ]; then
       if [ "$FORCE" == 1 ] || [ ! -f "$PLUGIN_DIR/maclbl.bin" ]; then
            if [ ! -f maclbl.txt ]; then
                printerr "macRecorder: cannot find file 'maclbl.txt'"
                return 1
            fi
           ./utils/mconv maclbl.txt
       fi
    fi
}

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(manuf.txt)
if [ $MACLBL -gt 0 ]; then
   EXTRAFILES+=(maclbl.bin)
fi

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
