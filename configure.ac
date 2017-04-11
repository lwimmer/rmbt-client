#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(rmbt-client, -, [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign -Wall -Werror -Wno-portability])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/rmbt.c])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES([UUID], [uuid])
PKG_CHECK_MODULES([JSON], [json-c])
PKG_CHECK_MODULES([SSL], [libssl libcrypto])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
