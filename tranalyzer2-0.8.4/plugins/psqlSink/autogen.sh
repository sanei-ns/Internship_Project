#!/usr/bin/env bash

# Plugin name
PLUGINNAME=psqlSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=923

# Dependencies (to be copied in PLUGIN_DIR)
#EXTRAFILES=(file3)

# Add extra compiler flags here
CFLAGS="-lpq"

# Dependencies (use this to report missing deps)
DEPS="libpq"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
