#!/usr/bin/env bash

PLUGINNAME="tranalyzer2"

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(proto.txt)

t2_postinst() {
    if [ $INSTALL ]; then
        ./install.sh all
    fi
}

# Source the main autogen.sh
. "$(dirname "$0")/../plugins/autogen.sh"
