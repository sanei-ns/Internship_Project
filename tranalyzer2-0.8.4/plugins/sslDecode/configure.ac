#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([sslDecode], [version-unused], [tranalyzer@rdit.ch])

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

AM_CONDITIONAL([APPLE], [test x$apple = xtrue])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
LT_INIT

# Checks for libraries.
AC_SEARCH_LIBS(
    [EVP_md5], [crypto], [],
    [AC_MSG_ERROR([openssl library not found])]
)

# Checks for header files.
AC_CHECK_HEADERS([openssl/md5.h], [],
    [AC_MSG_ERROR([<openssl/md5.h> header missing])])
AC_CHECK_HEADERS([openssl/pem.h], [],
    [AC_MSG_ERROR([<openssl/pem.h> header missing])])
AC_CHECK_HEADERS([openssl/sha.h], [],
    [AC_MSG_ERROR([<openssl/sha.h> header missing])])
AC_CHECK_HEADERS([openssl/x509.h], [],
    [AC_MSG_ERROR([<openssl/x509.h> header missing])])
AC_CHECK_HEADERS([openssl/x509v3.h], [],
    [AC_MSG_ERROR([<openssl/x509v3.h> header missing])])
AC_HEADER_STDBOOL
AC_HEADER_MAJOR

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memset mkdir regcomp strchr strerror])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
