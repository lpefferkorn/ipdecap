#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ipdecap], [0.7], [loic-ipdecap@loicp.eu])
AC_CANONICAL_HOST
AC_CONFIG_SRCDIR([src/ipdecap.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

case $host in
	*-*-freebsd*)
		CPPFLAGS="${CFLAGS} -I/usr/local/include -L/usr/local/lib"
		;;
esac

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_offline_filter, [],
             AC_MSG_ERROR(pcap library not found ))
AC_CHECK_LIB(crypto, EVP_CIPHER_CTX_init, [],
             AC_MSG_ERROR(OpenSSL library not found))

# Checks for header files.
AC_CHECK_HEADERS([string.h pcap/pcap.h pcap/vlan.h arpa/inet.h sys/types.h sys/socket.h getopt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT16_T
AC_CHECK_TYPES([struct ip, struct ether_addr, struct ether_header])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getopt_long memset strcspn strdup strtol])

# Used for unit tests
AC_CHECK_PROGS([MD5SUM], [md5sum md5 gmd5sum])
if test "x$MD5SUM" = x; then
  AC_MSG_WARN(Cannot find a md5 checkum tool. Unit tests cannot be run)
fi
AC_SUBST([MD5SUM])

AC_CONFIG_FILES([Makefile src/Makefile unit_tests/ip6in4/Makefile unit_tests/gre/Makefile unit_tests/esp/Makefile unit_tests/ipip/Makefile unit_tests/802.1q/Makefile])
AC_OUTPUT
