#!/usr/bin/env bash

cd "$(dirname "$0")/src/nDPI/" || exit 1

rm -rf aclocal.m4 autom4te.cache/ compile config.* configure \
       depcomp install-sh libndpi.pc libtool ltmain.sh \
       m4/libtool.m4 m4/lt~obsolete.m4 m4/ltoptions.m4 m4/ltsugar.m4 \
       m4/ltversion.m4 Makefile Makefile.in missing src/lib/Makefile.in \
       src/include/ndpi_config.h* src/include/stamp-h1 src/lib/.deps/ \
       src/include/ndpi_define.h \
       src/lib/Makefile src/lib/libndpi.so* src/lib/protocols/.deps/ \
       src/lib/protocols/.dirstamp src/lib/third_party/src/.deps/ \
       src/lib/third_party/src/.dirstamp stamp-h1
