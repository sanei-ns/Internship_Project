#!/usr/bin/env bash
#
# Update and convert the SSL Fingerprint Blacklist from
# https://raw.githubusercontent.com/trisulnsm/trisul-scripts/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...]\n\n"
    printf "Optional arguments:\n"
    printf "    -u      update blacklist\n"
    printf "    -c      convert blacklist\n"
    printf "    -a      update and convert blacklist\n"
    printf "    -f      file to convert\n"
    printf "    -h      display this help, then exit\n"
}

ssl_ja3_json_convert() {
    echo "% $($AWK '/^{/ { cnt++ } END { print cnt }' "$INFILE")" > "$OUTFILE"
    python -c '
import json

fingerprints = []
with open("ja3fingerprint.json") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fingerprints.append(json.loads(line))

for f in fingerprints:
    print("{}\t{}".format(f["ja3_hash"], f["desc"]))
    ' | sort >> "$OUTFILE"
}

ssl_ja3_csv_convert() {
    local hdr="% $($AWK '/^[[:xdigit:]]{32},"/ { cnt++ } END { print cnt }' "$INFILE")"
    $AWK -F, -v OFS='\t' '/^[[:xdigit:]]{32},"/ { print $1, $2 }' "$INFILE" | sort > "$OUTFILE"
    $SED -i "1s/^/$hdr\n/" "$OUTFILE"
}

ssl_ja3_update() {
    wget -N https://raw.githubusercontent.com/trisulnsm/trisul-scripts/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json
    #wget -N https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv

}

if [ $# -eq 0 ]; then
    printerr "One of '-a', '-u' or '-c' option is required"
    abort_with_help
fi

INFILE="ja3fingerprint.json"

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
        -f|--file)
            validate_next_file "$1" "$2"
            INFILE="$2"
            shift
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

OUTFILE="../$($AWK -F. -v OFS=. '{ $NF="tsv"; print }' <<< "$INFILE")"

RET=0

if [ "$UPDATE" ]; then
    ssl_ja3_update
    RET=$?
fi

if [ "$CONVERT" ]; then
    EXT="$($AWK -F. -v OFS=. '{ print $NF }' <<< "$INFILE")"
    if [ $EXT = "csv" ]; then
        ssl_ja3_csv_convert
    elif [ $EXT = "json" ]; then
        ssl_ja3_json_convert
    else
        printerr "Cannot determine format of input file (only *.csv and *.json are supported)"
        exit 1
    fi
    RET=$?
    if [ $RET -eq 0 ]; then
        printok "'$INFILE' successfully converted to '$OUTFILE'"
    else
        printerr "Failed to convert '$INFILE' to '$OUTFILE'"
    fi
fi

exit $RET
