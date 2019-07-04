#!/usr/bin/env bash

# Plugin name
PLUGINNAME=portClassifier

# Plugin execution order, as 3-digit decimal
PLUGINORDER=111

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(portmap.txt)

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
