#!/usr/bin/env bash

# Plugin name
PLUGINNAME=p0f

# Plugin execution order, as 3-digit decimal
PLUGINORDER=779

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(p0f-ssl.txt)

# Add necessary libraries here using -l option
#CFLAGS=""

# Dependencies (use this to report missing deps)
#DEPS=""

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
