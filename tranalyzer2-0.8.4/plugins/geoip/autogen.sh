#!/usr/bin/env bash

# Plugin name
PLUGINNAME=geoip

# Plugin execution order, as 3-digit decimal
PLUGINORDER=116

GEOIP_LEGACY=$(perl -nle 'print $1 if /^#define\s+GEOIP_LEGACY\s+(\d+).*$/' src/geoip.h)

# Dependencies (to be copied in PLUGIN_DIR)
if [ $GEOIP_LEGACY -eq 1 ]; then
    EXTRAFILES=(GeoLiteCity.dat.gz GeoLiteCityv6.dat.gz)
else
    EXTRAFILES=(GeoLite2-City.mmdb.gz)
fi

# Add necessary libraries here using -l option
if [ $GEOIP_LEGACY  -eq 1 ]; then
    LIBS="-lGeoIP"
else
    LIBS="-lmaxminddb"
fi

# Dependencies (use this to report missing deps)
if [ $GEOIP_LEGACY -eq 1 ]; then
    DEPS="GeoIP"
else
    DEPS="MaxMindDB"
fi

#t2_inst() {
#    local SRC="$1"
#    local DEST="${SRC%.gz}"
#    gunzip -c "$SRC" > "$PLUGIN_DIR/$DEST"
#    local RET=$?
#    if [ $RET -eq 0 ]; then
#        printf "\e[0;32m%s extracted into %s\e[0m\n" "$SRC" "$PLUGIN_DIR"
#    fi
#    return $RET
#}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
