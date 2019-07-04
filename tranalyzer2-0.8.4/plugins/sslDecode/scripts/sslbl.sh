#!/usr/bin/env bash
#
# Update and convert the SSL Fingerprint Blacklist from
# https://sslbl.abuse.ch/blacklist/sslblacklist.csv

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...]\n\n"
    printf "Optional arguments:\n"
    printf "    -u      update blacklist\n"
    printf "    -c      convert blacklist\n"
    printf "    -a      update and convert blacklist\n"
    printf "    -h      display this help, then exit\n"
}

sslbl_convert() {
    local hdr="% $($AWK '!/^#/ { cnt++ } END { print cnt }' "$INFILE")"
    $AWK -F, -v OFS='\t' '!/^#/ { print $2, $3 }' "$INFILE" | sort > "$OUTFILE"
    $SED -i "1s/^/$hdr\n/" "$OUTFILE"
    $SED -i "s/\r//" "$OUTFILE"
}

sslbl_update() {
    wget -N https://sslbl.abuse.ch/blacklist/sslblacklist.csv
}

if [ $# -eq 0 ]; then
    printerr "One of '-a', '-u' or '-c' option is required"
    abort_with_help
fi

INFILE="sslblacklist.csv"
OUTFILE="../$($AWK -F. -v OFS=. '{ $NF="tsv"; print }' <<< "$INFILE")"

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all)
            UPDATE=1
            CONVERT=1
            ;;
        -u|--update)
            UPDATE=1
            ;;
        -c|--convert)
            CONVERT=1
            ;;
        -h|-\?|--help)
            usage
            exit 0
            ;;
        *)
            abort_option_unknown "$1"
            ;;
    esac
    shift
done

RET=0

if [ "$UPDATE" ]; then
    sslbl_update
    RET=$?
fi

if [ "$CONVERT" ]; then
    sslbl_convert
    RET=$?
    if [ $RET -eq 0 ]; then
        printok "'$INFILE' successfully converted to '$OUTFILE'"
    else
        printerr "Failed to convert '$INFILE' to '$OUTFILE'"
    fi
fi

exit $RET
