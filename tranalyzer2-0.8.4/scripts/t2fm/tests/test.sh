#!/usr/bin/env bash

T2FMDIR="$(dirname "$0")/.."
source "$T2FMDIR/../t2utils.sh"
T2FMDIR="$($READLINK -f "$T2FMDIR")"

# Default values for command line arguments
FLOWFILE="$T2FMDIR/tests/x_flows.txt"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...] BACKEND_1 [BACKEND_2]\n"
    printf "\nBackends:\n"
    printf "    -m                  MongoDB\n"
    printf "    -p                  PostgreSQL\n"
    printf "    -t                  Tawk\n"
    printf "\nOptional arguments:\n"
    printf "    -d                  Run vimdiff when a test fails\n"
    printf "    -f                  Abort as soon as a test fails\n"
    printf "    -F file             Flow file to use for tawk tests [default: x_flows.txt]\n"
    printf "    -T from to          Only consider data between from and to [default: all]\n"
    printf "    -n num              Compute top num statistics [default: all]\n"
    printf "    test_name           A list of tests to run [default: all]\n\n"
    printf "    -?, -h, --help      Show help options and exit\n"
}

while [ $# -gt 0 ]; do
    case "$1" in
        # Backends
        -m|--mongo) BACKENDS+=(mongo);;
        -p|--postgres) BACKENDS+=(psql);;
        -t|--tawk) BACKENDS+=(tawk);;
        # Optional arguments
        -d|--diff) DIFF=1;;
        -f|--fatal) FATAL=1;;
        -F|--flow-file)
            validate_next_file "$1" "$2"
            FLOWFILE="$2"
            shift
            ;;
        -T)
            validate_next_num "$1" "$2"
            validate_next_num "$1" "$3"
            TIME_FROM="$($TAWK '{ print timestamp($1) }' <<< "$2")"
            TIME_TO="$($TAWK '{ print timestamp($1) }' <<< "$3")"
            shift  # TIME_FROM
            shift  # TIME_TO
            ;;
        -n|--top-n)
            validate_next_num "$1" "$2"
            TOP_N="$2"
            shift
            ;;
        -\?|-h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -f "$T2FMDIR/tawk/$1" ]; then
                TESTS+=("$1")
            elif [ -f "$1" ]; then
                _FOLDER="$($AWK -F'/' 'NF > 1 { print $(NF-1) }' <<< "$1")"
                _FNAME="$($AWK -F'/' 'NF > 1 { print $NF }' <<< "$1")"
                TESTS+=("$_FNAME")
            else
                abort_option_unknown "$1"
            fi
            ;;
    esac
    shift
done

NUM_BACKENDS="${#BACKENDS[*]}"
if [ $NUM_BACKENDS -eq 0 ]; then
    printerr "One or two backends are required"
    abort_with_help
elif [ $NUM_BACKENDS -gt 2 ]; then
    printerr "A maximal of two backends can be specified"
    abort_with_help
fi

if [ -z "$TESTS" ]; then
    for i in "${BACKENDS[@]}"; do
        TESTS+=($(ls -1 "$T2FMDIR/$i/"))
    done
    TESTS=($(printf '%s\n' "${TESTS[@]}" | sort -u))
fi

setup_mongo() {
    CMD_MONGO=(mongo --quiet tranalyzer)

    "${CMD_MONGO[@]}" --eval 'db.getName()' &> /dev/null
    if [ $? -ne 0 ]; then
        printerr "MongoDB server is not running"
        exit 1
    fi

    local count
    count="$("${CMD_MONGO[@]}" --eval 'db.flow.count()')"
    if [ "$count" -eq 0 ]; then
        printerr "MongoDB collection 'flow' from DB 'tranalyzer' is empty"
        exit 1
    fi

    local top_n="$TOP_N"
    if [ -z "$top_n" ]; then
        top_n="$count"
    fi

    local time_from="$TIME_FROM"
    if [ -z "$time_from" ]; then
        time_from="$("${CMD_MONGO[@]}" "$T2FMDIR/mongo/min_time")"
        time_from="$($TAWK '{ print utc($1) }' <<< "$time_from")"
    fi

    local time_to="$TIME_TO"
    if [ -z "$time_to" ]; then
        time_to="$("${CMD_MONGO[@]}" "$T2FMDIR/mongo/max_time")"
        time_to="$($TAWK '{ print utc($1) }' <<< "$time_to")"
    fi

    CMD_MONGO+=(
        --eval "const n = $top_n, \
                      time_from = new ISODate('$time_from'), \
                      time_to = new ISODate('$time_to');"
    )
}

setup_psql() {
    CMD_PSQL=(psql -U postgres)

    local tables
    tables="$("${CMD_PSQL[@]}" -l 2> /dev/null)"
    if [ $? -ne 0 ]; then
        printerr "PostgreSQL server is not running"
        exit 1
    fi

    if [ -z "$($AWK -F'|' "\$1 ~ /^\s*tranalyzer\s*$/" <<< "$tables")" ]; then
        printerr "PostgreSQL table 'tranalyzer' not found"
        exit 1
    fi

    CMD_PSQL+=(-d tranalyzer -A -t -F $'\t')

    local top_n="$TOP_N"
    if [ -z "$top_n" ]; then
        top_n="$("${CMD_PSQL[@]}" -c 'select count(*) from flow')"
    fi

    local time_from="$TIME_FROM"
    if [ -z "$time_from" ]; then
        time_from="$("${CMD_PSQL[@]}" -f "$T2FMDIR/psql/min_time")"
    fi

    local time_to="$TIME_TO"
    if [ -z "$time_to" ]; then
        time_to="$("${CMD_PSQL[@]}" -f "$T2FMDIR/psql/max_time")"
    fi

    CMD_PSQL+=(
        -v n="$top_n"
        -v time_from="$time_from"
        -v time_to="$time_to"
        -f
    )
}

setup_tawk() {
    if [ ! -f "$FLOWFILE" ]; then
        printerr "Flow file '$FLOWFILE' does not exist"
        exit 1
    fi

    CMD_TAWK=($TAWK -t -I "$FLOWFILE")

    local top_n="$TOP_N"
    if [ -z "$top_n" ]; then
        top_n="$("${CMD_TAWK[@]}" '!hdr() { flows++ } END { print flows }')"
    fi

    local time_from="$TIME_FROM"
    if [ -z "$time_from" ]; then
        time_from="$("${CMD_TAWK[@]}" -f "$T2FMDIR/tawk/min_time")"
    fi

    local time_to="$TIME_TO"
    if [ -z "$time_to" ]; then
        time_to="$("${CMD_TAWK[@]}" -f "$T2FMDIR/tawk/max_time")"
    fi

    CMD_TAWK+=(
        -v n="$top_n"
        -v time_from="$time_from"
        -v time_to="$time_to"
        -f
    )
}

setup_backends() {
    for backend in "${BACKENDS[@]}"; do
        case "$backend" in
            mongo) setup_mongo;;
            psql) setup_psql;;
            tawk) setup_tawk;;
            *)
                printerr "Unknown backend '$1'"
                exit 1
                ;;
        esac
    done
}

run_test() {
    local backend="$1"
    case "$backend" in
        mongo) "${CMD_MONGO[@]}" "$backend/$test_name";;
        psql) "${CMD_PSQL[@]}" "$backend/$test_name";;
        tawk) "${CMD_TAWK[@]}" "$backend/$test_name";;
    esac
}

setup_backends

for test_name in ${TESTS[@]}; do
    error=0
    for backend in "${BACKENDS[@]}"; do
        if [ ! -f "$backend/$test_name" ]; then
            printerr "Test '$backend/$test_name' does not exist"
            error=1
        fi
    done

    [ $error -ne 0 ] && continue

    OUT=()
    for backend in "${BACKENDS[@]}"; do
        OUT+=("$(run_test "$backend")")
    done

    printf "Test '$test_name': "
    if [ $NUM_BACKENDS -eq 1 ]; then
        printf "\n\n${OUT[0]}\n"
    elif [ "${OUT[0]}" = "${OUT[1]}" ]; then
        printok "PASS"
    else
        OUT_SORTED[0]="$(sort <<< "${OUT[0]}")"
        OUT_SORTED[1]="$(sort <<< "${OUT[1]}")"
        if [ "${OUT_SORTED[0]}" = "${OUT_SORTED[1]}" ]; then
            printok "PASS"
        else
            printerr "FAIL"
            if [ "$DIFF" ]; then
                TMP=()
                for ((i = 0; i < $NUM_BACKENDS; i++)); do
                    tmp="/tmp/t2fm_test_${test_name}_${BACKENDS[$i]}"
                    echo "${OUT_SORTED[$i]}" > "$tmp"
                    TMP+=("$tmp")
                done
                vimdiff "${TMP[@]}"
                rm -f "${TMP[@]}"
            fi
            [ "$FATAL" ] && exit 1
        fi
    fi
done
