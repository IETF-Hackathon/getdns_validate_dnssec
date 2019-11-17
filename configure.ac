AC_PREREQ([2.68])
AC_INIT([getdns_validate_dnssec], [0.1.0], [willem@nlnetlabs.nl])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/getdns_validate_dnssec.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

AC_CHECK_LIB([getdns], [getdns_validate_dnssec2],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.1.0 ])],)
AC_CHECK_HEADER([getdns/getdns_extra.h],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.1.0 ])],)

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
