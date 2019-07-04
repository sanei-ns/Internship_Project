#!/usr/bin/env bash
#
# List plugins and their numbers.
# If no argument is passed, then the output is tab separated.
# Otherwise in LaTeX format

source "$(dirname "$0")/../scripts/t2utils.sh"

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...]"
    echo
    echo "Optional arguments:"
    echo "    -n                Sort by plugin numbers instead of plugin names"
    echo "    -t                Output the table in LaTeX format"
    echo
    echo "    -h, --help        Show this help, then exit"
}

SORTCMD="cat"

while [ $# -ne 0 ]; do
    case "$1" in
        -n)
            SORTCMD="sort -t= -nk2"
            ;;
        -t|--tex|--latex)
            TEX=1
            ;;
        -h|-\?|--help) usage; exit 0;;
        *)
            abort_option_unknown "$1"
            ;;
    esac
    shift
done

grep -RHi pluginorder= $T2PLHOME/*/autogen.sh | uniq | $SORTCMD | \
    $AWK -v tex="$TEX" '
        BEGIN {
            if (tex) {
                print "\\begin{center}"
                print "\\begin{tabular}{lc}"
                print "\\toprule"
                print "{\\bf Plugin} & {\\bf Number}\\\\"
                print "\\midrule"
            }
        }
        {
            split($1, A, ":");
            n = split(A[1], B, "/");
            split(A[2], C, "=");
            if (tex) {
                printf "%s & %s\\\\\n", B[n-1], C[2]
            } else {
                printf "%s\t%s\n", B[n-1], C[2]
            }
        }
        END {
            if (tex) {
                print "\\bottomrule"
                print "\\end{tabular}"
                print "\\end{center}"
            }
        }'
