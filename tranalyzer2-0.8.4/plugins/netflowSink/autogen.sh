#!/usr/bin/env bash

# Plugin name
PLUGINNAME=netflowSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=904

t2_prebuild() {
    # prep .h file
    utils/ampls
}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
