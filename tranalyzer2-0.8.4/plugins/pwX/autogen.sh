#!/usr/bin/env bash

# Plugin name
PLUGINNAME=pwX

# Plugin execution order, as 3-digit decimal
PLUGINORDER=602

# Add necessary libraries here using -l option
CFLAGS="-Wundef"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
