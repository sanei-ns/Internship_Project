#!/usr/bin/env bash

# Plugin name
PLUGINNAME=sqliteSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=924

# Dependencies (to be copied in PLUGIN_DIR)
#EXTRAFILES=(file3)

# Add extra compiler flags here
CFLAGS="-lsqlite3"

# Dependencies (use this to report missing deps)
DEPS="sqlite"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
