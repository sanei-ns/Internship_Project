#!/usr/bin/env bash
#
# Generates a KML file from a flow file
# (map latitude/longitude with Google Earth)
#
# Output file name derived from input file name.
#   - FILE_flows.txt => FILE.kml
#   - FILE.txt => FILE.kml
#
# Green: source
# Red: destination

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Generates a KML file from a flow file (map latitude/longitude with Google Earth)\n\n"
    printf "Usage:\n"
    printf "    $SNAME [OPTION...] <FILE_flows.txt>\n\n"
    printf "Optional arguments:\n"
    printf "    --src-only   only display source IP of flows\n"
    printf "    --dst-only   only display destination IP of flows\n\n"
    printf "    --no-icmp    do not display IPs from ICMP flows\n"
    printf "    --no-tcp     do not display IPs from TCP flows\n"
    printf "    --no-udp     do not display IPs from UDP flows\n\n"
    printf "    --no-dport   do not display IPs from flows with ports > 1024\n\n"
    #printf "    --icmp-only only display IPs for ICMP flows\n"
    #printf "    --tcp-only  only display IPs for TCP flows\n"
    #printf "    --udp-only  only display IPs for UDP flows\n"
    printf "    -h, --help  display this help and exit\n"
}

src=1
dst=1
icmp=1
tcp=1
udp=1
dport=1

while [ $# -gt 0 ]; do
    case "$1" in
        --src-only) dst=0;;
        --dst-only) src=0;;
        --no-icmp) icmp=0;;
        --no-tcp) tcp=0;;
        --no-udp) udp=0;;
        #--icmp-only) ;;
        #--tcp-only) ;;
        #--udp-only) ;;
        --no-dport) dport=0;;
        #--icmp-only) ;;
        -h|-\?|--help)
            usage
            exit 0
            ;;
        *)
            if [ ! -f "$1" ]; then
                abort_option_unknown "$1"
            fi
            FILE="$1"
            ;;
    esac
    shift
done

if [ ! -f "$FILE" ]; then
    abort_required_file
fi

OUT="$(basename "$FILE" _flows.txt)"
if [ "$OUT" = "$FILE" ]; then
    OUT="$(basename "$FILE" .txt)"
fi
OUT="${OUT}.kml"

cat << EOF > "$OUT"
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>IP Connections</name>
    <description>IP Connections</description>
    <Style id="redPlacemark">
      <IconStyle>
        <color>ff0000ff</color>
      </IconStyle>
    </Style>
    <Style id="greenPlacemark">
      <IconStyle>
        <color>ff00ff00</color>
      </IconStyle>
    </Style>
EOF

TMP=`(tempfile) 2> /dev/null` || TMP=/tmp/test$$
$AWK -F'\t' -v src=$src -v dst=$dst -v icmp=$icmp -v tcp=$tcp -v udp=$udp -v dport=$dport '
    /^#/ { next } # skip comments

    /^%/ && $1 ~ /^%[[:space:]]*dir$/ {
        dir = 1
        for (i = 2; i <= NF; i++) {
            if ($i == "flowStat") flow_stat = i
            else if ($i == "srcIP4" || $i == "srcIP6" || $i == "srcIP") src_ip = i
            else if ($i == "dstIP4" || $i == "dstIP6" || $i == "dstIP") dst_ip = i
            else if ($i == "srcPort") src_port = i
            else if ($i == "dstPort") dst_port = i
            else if ($i == "l4Proto") proto = i
            # BasicFlow
            else if ($i == "srcIPLng_Lat_relP") { src_lat = i; src_lon = i }
            else if ($i == "dstIPLng_Lat_relP") { dst_lat = i; dst_lon = i }
            # GeoIP (only if lat/long not found in basicFlow)
            else if ($i == "srcIpLat" && src_lat == 0) src_lat = i
            else if ($i == "srcIpLong" && src_long == 0) src_lon = i
            else if ($i == "dstIpLat" && dst_lat == 0) dst_lat = i
            else if ($i == "dstIpLong" && dst_long == 0) dst_lon = i
        }
        if (src_lat == 0 || src_lon == 0 || dst_lat == 0 || dst_lon == 0) {
            print "One of src/dst IP lat/long column could not be found"
            exit
        }
        if (flow_stat == 0 || src_ip == 0 || dst_ip == 0 ||
            proto == 0 || src_port == 0 || dst_port == 0)
        {
            print "One of flowStat, l4Proto, src/dst IP4 column could not be found"
            exit
        }
    }

    /^%/ { next } # skip special comments

    {
        if (proto != 0) {
            if (!icmp && $proto ==  1) next
            if (!tcp  && $proto ==  6) next
            if (!udp  && $proto == 17) next
        }

        if (!dport && srcPort > 1024 && dstPort > 1024) next

        client = ((flow_stat != 0 && and($flow_stat, 1) == 0) || $dir == "A")

        if (src) {
            if (( client && ($src_lat != 0 || $src_lon != 0)) ||
                (!client && ($dst_lat != 0 || $dst_lon != 0)))
            {
                printf "<Placemark>"
                printf "<styleUrl>#greenPlacemark</styleUrl>"
                if (client && src_ip != 0) {
                    printf "<description>" $src_ip "</description>"
                } else if (!client && dst_ip != 0) {
                    printf "<description>" $dst_ip "</description>"
                }
                printf "<Point>"
                printf "<coordinates>"
                if (client) {
                    if (src_lat != src_lon) {
                        printf $src_lon ", " $src_lat ", 0."
                    } else {
                        split($src_lat, l, "_")
                        if (l[1] != 666 && l[2] != 666) {
                            printf l[1] ", " l[2] ", 0."
                        }
                    }
                } else {
                    if (dst_lat != dst_lon) {
                        printf $dst_lon ", " $dst_lat ", 0."
                    } else {
                        split($dst_lat, l, "_")
                        if (l[1] != 666 && l[2] != 666) {
                            printf l[1] ", " l[2] ", 0."
                        }
                    }
                }
                printf "</coordinates>"
                printf "</Point>"
                printf "</Placemark>\n"
            }
        }

        if (dst) {
            if (( client && ($dst_lat != 0 || $dst_lon != 0)) ||
                (!client && ($src_lat != 0 || $src_lon != 0)))
            {
                printf "<Placemark>"
                printf "<styleUrl>#redPlacemark</styleUrl>"
                if (client && dst_ip != 0) {
                    printf "<description>" $dst_ip "</description>"
                } else if (!client && src_ip != 0) {
                    printf "<description>" $src_ip "</description>"
                }
                printf "<Point>"
                printf "<coordinates>"
                if (client) {
                    if (dst_lat != dst_lon) {
                        printf $dst_lon ", " $dst_lat ", 0."
                    } else {
                        split($dst_lat, l, "_")
                        if (l[1] != 666 && l[2] != 666) {
                            printf l[1] ", " l[2] ", 0."
                        }
                    }
                } else {
                    if (src_lat != src_lon) {
                        printf $src_lon ", " $src_lat ", 0."
                    } else {
                        split($src_lat, l, "_")
                        if (l[1] != 666 && l[2] != 666) {
                            printf l[1] ", " l[2] ", 0."
                        }
                    }
                }
                printf "</coordinates>"
                printf "</Point>"
                printf "</Placemark>\n"
            }
        }

        #print "<Placemark>"
        #print "  <LineString>"
        #print "    <coordinates>"
        #print "      " $src_lon ", " $src_lat ", 0."
        #print "      " $dst_lon ", " $dst_lat ", 0."
        #print "    </coordinates>"
        #print "  </LineString>"
        #print "</Placemark>"
    }
' "$FILE" > "$TMP"

sort -u "$TMP" >> "$OUT"

cat << EOF >> "$OUT"
  </Document>
</kml>
EOF
