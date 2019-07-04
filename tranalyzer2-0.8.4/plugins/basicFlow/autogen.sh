#!/usr/bin/env bash

# Plugin name
PLUGINNAME=basicFlow

# Plugin execution order, as 3-digit decimal
PLUGINORDER=100

IPV6_ACTIVATE=$(perl -nle 'print $1 if /^#define\s+IPV6_ACTIVATE\s+(\d+).*$/' ../../tranalyzer2/src/networkHeaders.h)
SUBNET_TEST=$(perl -nle 'print $1 if /^#define\s+BFO_SUBNET_TEST\s+(\d+).*$/' src/basicFlow.h)
SUBNET_TEST_GRE=$(perl -nle 'print $1 if /^#define\s+BFO_SUBNET_TEST_GRE\s+(\d+).*$/' src/basicFlow.h)
SUBNET_TEST_L2TP=$(perl -nle 'print $1 if /^#define\s+BFO_SUBNET_TEST_L2TP\s+(\d+).*$/' src/basicFlow.h)

if [ $SUBNET_TEST -eq 1 ]; then
    BUILD_SUBNET_FILE=1
elif [ $IPV6_ACTIVATE -ne 1 ] && [ $SUBNET_TEST_GRE -eq 1 -o $SUBNET_TEST_L2TP -eq 1 ]; then
    BUILD_SUBNET_FILE=1
else
    BUILD_SUBNET_FILE=0
fi

t2_clean() {
    make -C utils distclean
    make -C tor distclean
    rm -f subnets4_HL* subnets6_HL*
}

if [ $BUILD_SUBNET_FILE -eq 1 ]; then
    # prepare the subnet files
    t2_preinst() {
        # Subnet file for IPv4
        if [ $IPV6_ACTIVATE -ne 1 ]; then
            if [ "$FORCE" != 1 ] && [ -f subnets4.txt ] && [ -f subnets4.txt.bz2 ]; then
                bz2_version=`bzcat subnets4.txt.bz2 | head -1 | awk -F"\t" '{ print $2, $3 }'`
                txt_version=`awk -F"\t" 'NR==1 {print $2, $3; exit;}' subnets4.txt`
                # if "./autogen.sh -f" and subnets4.txt.bz2 version+rev is different from subnets4.txt version+rev
                if [ "$bz2_version" != "$txt_version" ]; then
                    printwrn "subnets4.txt(.bz2) files version differ"
                    printinf "Run ./autogen.sh -f to overwrite your subnets4.txt"
                fi
            fi
            if [ ! -f "$PLUGIN_DIR/subnets4_HLP.bin" ] || [ "$FORCE" = 1 ]; then
                printinf "Converting 'subnets4.txt' to binary, this may take a minute"
                if [ ! -f subnets4.txt ] || [ "$FORCE" = 1 ]; then
                    bzip2 -dfk subnets4.txt.bz2 || exit 1
                fi
                ./utils/subconv -4 -t subnets4.txt || exit 1
            fi
        fi

        # Subnet file for IPv6
        if [ $IPV6_ACTIVATE -ge 1 ]; then
            if [ "$FORCE" != 1 ] && [ -f subnets6.txt ] && [ -f subnets6.txt.bz2 ]; then
                bz2_version=`bzcat subnets6.txt.bz2 | head -1 | awk -F"\t" '{ print $2, $3 }'`
                txt_version=`awk -F"\t" 'NR==1 {print $2, $3; exit;}' subnets6.txt`
                # if "./autogen.sh -f" and subnets6.txt.bz2 version+rev is different from subnets6.txt version+rev
                if [ "$bz2_version" != "$txt_version" ]; then
                    printwrn "subnets6.txt(.bz2) files version differ"
                    printinf "Run ./autogen.sh -f to overwrite your subnets6.txt"
                fi
            fi
            if [ ! -f "$PLUGIN_DIR/subnets6_HLP.bin" ] || [ "$FORCE" = 1 ]; then
                printinf "Converting 'subnets6.txt' to binary, this may take a minute"
                if [ ! -f subnets6.txt ] || [ "$FORCE" = 1 ]; then
                    bzip2 -dfk subnets6.txt.bz2 || exit 1
                fi
                ./utils/subconv -6 subnets6.txt || exit 1
            fi
        fi
    }
fi

if [ $BUILD_SUBNET_FILE -eq 1 ]; then
    # Dependencies (to be copied in PLUGIN_DIR)
    if [ $IPV6_ACTIVATE -ne 1 ]; then
      EXTRAFILES+=(subnets4_HLP.bin)
    fi
    if [ $IPV6_ACTIVATE -gt 0 ]; then
      EXTRAFILES+=(subnets6_HLP.bin)
    fi
fi

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
