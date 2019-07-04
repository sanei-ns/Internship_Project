#!/usr/bin/env bash

merge_lines() {
    hdr="$1"
    shift
    ls -1 "$@" | sed -re "1s/^/${hdr} = /" -re '2,$s/^/    /' -re '$!s/$/ \\/'
}

fatal() {
    echo "$@" >&2
    exit 1
}

cd "$(dirname "$0")"
cd src/nDPI/ || fatal "missing nDPI source directory"

# reduce size
rm -rf doc/ example/ packages/ tests/ wireshark/ .git/ .gitignore .travis.yml || \
    fatal "failed to remove additional files/directories"

# create configure.ac from configure.seed
([ -e autogen.sh ] && [ -e configure.seed ]) || fatal "nDPI autogen.sh or configure.seed not found"
sed '/^autoreconf/,$d' autogen.sh > autogen.tmp
mv autogen.tmp autogen.sh
chmod 755 autogen.sh
./autogen.sh
[ -e configure.ac ] || fatal "failed to generate configure.ac"
rm autogen.sh configure.seed

# create the Makefile.am for nDPI static library
cd src/lib/ || fatal "nDPI library directory not found"
[ -e Makefile.in ] || fatal "missing Makefile.in"
rm Makefile.in

cat << EOF > Makefile.am
noinst_LTLIBRARIES = libndpi.la

CFLAGS += -fPIC -DPIC # --coverage
libndpi_la_CPPFLAGS = -I\$(top_srcdir)/src/include/  -I\$(top_srcdir)/src/lib/third_party/include/ @HS_INC@

libndpi_la_includedir = \$(includedir)/libndpi-@VERSION@/libndpi

EOF

merge_lines "libndpi_la_include_HEADERS" ../include/*.h third_party/include/*.h >> Makefile.am
echo >> Makefile.am
merge_lines "libndpi_la_SOURCES" ndpi_content_match.c.inc ndpi_main.c protocols/*.c third_party/src/*.c >> Makefile.am
