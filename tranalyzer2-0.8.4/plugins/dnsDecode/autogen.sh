#!/usr/bin/env bash

# Plugin name
PLUGINNAME=dnsDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=251

MALTEST=$(perl -nle 'print $1 if /^#define\s+MAL_TEST\s+(\d+).*$/' src/dnsDecode.h)

if [ $MALTEST -gt 0 ]; then
    t2_preinst() {
        if [ ! -f "$PLUGIN_DIR/maldm.txt" ] || [ "$FORCE" = 1 ]; then
            printinf "Preparing 'maldomain.txt'"
            ./utils/dmt maldomain.txt
        fi
    }

    # Dependencies (to be copied in PLUGIN_DIR)
    EXTRAFILES=(maldm.txt)
fi

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
