#!/usr/bin/env bash

# Plugin name
PLUGINNAME=mysqlSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=925

# Dependencies (to be copied in PLUGIN_DIR)
#EXTRAFILES=(file3)

# Dependencies (use this to report missing deps)
DEPS="libmysqlclient"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
