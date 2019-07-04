#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([txtSink], [version-unused], [tranalyzer@rdit.ch])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src])

case $OSTYPE in
    darwin*)
        AM_INIT_AUTOMAKE
        ;;
    linux*)
        AM_INIT_AUTOMAKE
        ;;
esac

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FSEEKO
AC_CHECK_FUNCS([gettimeofday strerror uname])

# If GZ_COMPRESS is set, we need to include gz2txt.c (see src/Makefile.am)
GZ_COMPRESS=`perl -nle 'print $1 if /^#define\s+GZ_COMPRESS\s+(\d+).*$/' src/txtSink.h`
AM_CONDITIONAL([GZ_COMPRESS_SET], [test x$GZ_COMPRESS = x1])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
