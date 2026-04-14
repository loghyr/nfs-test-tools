# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# configure.ac -- autoconf input for nfs-test-tools
#
AC_INIT([nfs-test-tools], [0.1], [loghyr@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O

# Required: OpenSSL for TLS
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0], [],
    [AC_MSG_ERROR([OpenSSL >= 1.1.0 is required (install openssl-devel or libssl-dev)])])

# Optional: GSSAPI for Kerberos tests
# Try mit-krb5-gssapi pkg-config name first, then krb5, then direct lib check
have_gssapi=no
PKG_CHECK_MODULES([GSSAPI], [mit-krb5-gssapi], [have_gssapi=yes], [
    PKG_CHECK_MODULES([GSSAPI], [krb5], [have_gssapi=yes], [
        AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context],
            [AC_CHECK_HEADERS([gssapi/gssapi.h], [
                have_gssapi=yes
                GSSAPI_CFLAGS=""
                GSSAPI_LIBS="-lgssapi_krb5"
            ])])
    ])
])
AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])
AM_CONDITIONAL([HAVE_GSSAPI], [test "x$have_gssapi" = xyes])

# Check for <krb5.h> for numeric minor-status classification table.
# Use GSSAPI_CFLAGS so the include path matches the selected GSSAPI library.
have_krb5_h=no
AS_IF([test "x$have_gssapi" = xyes], [
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $GSSAPI_CFLAGS"
    AC_CHECK_HEADERS([krb5.h], [have_krb5_h=yes])
    CPPFLAGS="$save_CPPFLAGS"
])
AM_CONDITIONAL([HAVE_KRB5_H], [test "x$have_krb5_h" = xyes])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT

echo ""
echo "nfs-test-tools configuration:"
echo "  OpenSSL  : yes"
echo "  GSSAPI   : $have_gssapi"
echo "  krb5.h   : $have_krb5_h (numeric minor-status table)"
echo ""
