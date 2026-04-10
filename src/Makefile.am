# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: Apache-2.0

bin_PROGRAMS = nfs_tls_test nfs_cert_info nfs_tls_server

nfs_tls_test_SOURCES = \
	nfs_tls_test.c \
	tls_client.c \
	tls_stat.c \
	diagnose.c

nfs_tls_test_CFLAGS  = $(OPENSSL_CFLAGS)
nfs_tls_test_LDADD   = $(OPENSSL_LIBS) -lm -lpthread

nfs_cert_info_SOURCES = \
	nfs_cert_info.c \
	diagnose.c

nfs_cert_info_CFLAGS = $(OPENSSL_CFLAGS)
nfs_cert_info_LDADD  = $(OPENSSL_LIBS)

nfs_tls_server_SOURCES = nfs_tls_server.c
nfs_tls_server_CFLAGS  = $(OPENSSL_CFLAGS)
nfs_tls_server_LDADD   = $(OPENSSL_LIBS)

if HAVE_GSSAPI
bin_PROGRAMS += nfs_krb5_test

nfs_krb5_test_SOURCES = nfs_krb5_test.c
nfs_krb5_test_CFLAGS  = $(GSSAPI_CFLAGS)
nfs_krb5_test_LDADD   = $(GSSAPI_LIBS)
endif
