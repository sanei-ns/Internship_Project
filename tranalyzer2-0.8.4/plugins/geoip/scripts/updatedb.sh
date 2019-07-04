#!/usr/bin/env bash

cd "$(dirname "$0")/.."
wget -N http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
