#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([Tranalyzer], [0.8.4], [tranalyzer@rdit.ch])

AC_DEFINE([CODENAME], ["Anteater"], [Codename of package])
AC_DEFINE([RELEASE_TYPE], ["Tarantula"], [Development status of package])
AC_DEFINE([APPNAME], [PACKAGE_NAME], [Alternative name for PACKAGE_NAME])
AC_DEFINE([APPVERSION], [PACKAGE_VERSION], [Alternative name for PACKAGE_VERSION])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src])

case $OSTYPE in
    darwin*)
        AM_INIT_AUTOMAKE
        apple=true
        ;;
    linux*)
        AM_INIT_AUTOMAKE
        LTLDFLAGS="-Wl,-export-dynamic"
        ;;
esac

AM_CONDITIONAL([APPLE], [test x$apple = xtrue])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([m], [pow])
AC_CHECK_LIB([pthread], [pthread_create])

AC_SEARCH_LIBS([pcap_open_offline], [pcap], [], [AC_MSG_ERROR([libpcap or libpcap-dev not found])])

# Checks for header files.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([ \
    arpa/inet.h \
    float.h \
    inttypes.h \
    limits.h \
    netinet/in.h \
    stddef.h \
    stdint.h \
    stdlib.h \
    string.h \
    sys/ioctl.h \
    sys/socket.h \
    sys/time.h \
    unistd.h
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([ \
    alarm \
    gettimeofday \
    isascii \
    memchr \
    memset \
    pow \
    strdup \
    strerror \
    strrchr \
    strtoul \
    strtoull
])

AC_SUBST([AM_CFLAGS])
AC_SUBST(LTLDFLAGS)

AC_CONFIG_FILES([
    Makefile
    man/Makefile
    src/Makefile
])
AC_OUTPUT
