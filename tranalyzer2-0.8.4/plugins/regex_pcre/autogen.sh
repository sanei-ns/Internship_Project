#!/usr/bin/env bash

# Plugin name
PLUGINNAME=regex_pcre

# Plugin execution order, as 3-digit decimal
PLUGINORDER=603

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(regexfile.txt)

# Dependencies (use this to report missing deps)
DEPS="pcre"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
