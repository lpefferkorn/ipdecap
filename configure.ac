#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ipdecap], [0.6], [loic-ipdecap@loicp.eu])
AC_CONFIG_SRCDIR([src/ipdecap.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_offline_filter, [], AC_MSG_ERROR(pcap
             library not found ))
AC_CHECK_LIB(crypto, EVP_CIPHER_CTX_init, [],
             AC_MSG_ERROR(OpenSSL library not found))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strcspn strdup strtol])

AC_CONFIG_FILES([Makefile src/Makefile])
#                 unit_tests/802.1q/Makefile
#                 unit_tests/Makefile
#                 unit_tests/esp/Makefile
#                 unit_tests/gre/Makefile
#                 unit_tests/ip6in4/Makefile
#                 unit_tests/ipip/Makefile])
AC_OUTPUT
