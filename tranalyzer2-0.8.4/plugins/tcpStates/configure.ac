#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([tcpStates], [version-unused], [tranalyzer@rdit.ch])

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

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
