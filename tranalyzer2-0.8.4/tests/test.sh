#!/usr/bin/env bash
#
# Call this script from a plugin main folder, e.g.,
#
#     cd $T2HOME/plugins/t2PSkel/
#     ../../tests/test.sh

PNAME="$(basename "$PWD")"
if [ "$PNAME" = "tests" ]; then
    echo "Changing directory (cd ..)..."
    cd ..
    PNAME="$(basename "$PWD")"
fi

TESTER="../tests/Tester.py"
if [ "$PNAME" != "tranalyzer2" ]; then
    TESTER="../$TESTER"
fi

"$TESTER" -f "tests/${PNAME}.flags" $@
