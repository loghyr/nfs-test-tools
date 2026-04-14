# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only

if HAVE_GSSAPI

check_PROGRAMS = krb5_parser_tests

krb5_parser_tests_SOURCES = \
	krb5_parser_tests.c \
	../src/gss_wire.c

krb5_parser_tests_CFLAGS = \
	$(GSSAPI_CFLAGS) \
	-I$(top_srcdir)/src

krb5_parser_tests_LDADD = $(GSSAPI_LIBS)

TESTS = krb5_parser_tests

endif # HAVE_GSSAPI
