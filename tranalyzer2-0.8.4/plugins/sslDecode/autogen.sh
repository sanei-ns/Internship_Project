#!/usr/bin/env bash

# Plugin name
PLUGINNAME=sslDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=315

# Add extra compiler flags here
CFLAGS="-Wundef"

EXTRAFILES=(ja3fingerprint.tsv sslblacklist.tsv)

# Add necessary libraries here using -l option
if [ "$(uname)" = "Darwin" ]; then
    CFLAGS="-I/usr/local/opt/openssl/include"
    LIBS="-L/usr/local/opt/openssl/lib"
else
    LIBS="-lssl -lcrypto"
fi

# Dependencies (use this to report missing deps)
DEPS="libssl"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
