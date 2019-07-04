#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([mongoSink], [version-unused], [tranalyzer@rdit.ch])

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
        ;;
esac

AM_CONDITIONAL([APPLE], [test x$apple = xtrue])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([LIBMONGOC], [libmongoc-1.0])
PKG_CHECK_MODULES([LIBBSON], [libbson-1.0])
#AC_CHECK_LIB([libmongoc-1.0], [mongoc_init])
#AC_CHECK_LIB([libbson-1.0], [bson_new])

# Checks for header files.
AC_HEADER_STDBOOL
#AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
#AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
