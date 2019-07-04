#!/usr/bin/env bash

# Plugin name
PLUGINNAME=protoStats

# Plugin execution order, as 3-digit decimal
PLUGINORDER=001

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(ethertypes.txt portmap.txt proto.txt)

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
