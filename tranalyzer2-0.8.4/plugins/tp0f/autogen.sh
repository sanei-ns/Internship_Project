#!/usr/bin/env bash

# Plugin name
PLUGINNAME=tp0f

# Plugin execution order, as 3-digit decimal
PLUGINORDER=117

#t2_preinst() {
#    ./tp0fL34conv p0f.fp > tp0fL34.txt
#}

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(tp0fL34.txt)

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
