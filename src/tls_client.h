/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tls_client.h -- RFC 9289 STARTTLS connection interface.
 *
 * Implements the client side of RPC-over-TLS (RFC 9289):
 *   1. TCP connect to the server.
 *   2. Send a NULL RPC call with AUTH_TLS (flavor 7) credential.
 *   3. Verify the server returns an RPC_SUCCESS reply.
 *   4. Perform TLS handshake; negotiate ALPN "sunrpc".
 *   5. Optionally send a post-TLS NULL RPC call to confirm the session works.
 */

#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <stddef.h>
#include <openssl/ssl.h>

/*
 * struct tls_conn -- holds state for one STARTTLS connection.
 *
 * tc_fd  : underlying TCP socket (valid until tls_conn_close())
 * tc_ctx : SSL_CTX shared across connections (not owned; do not free here)
 * tc_ssl : per-connection SSL object (freed by tls_conn_close())
 */
struct tls_conn {
    int      tc_fd;
    SSL_CTX *tc_ctx;
    SSL     *tc_ssl;
};

/*
 * tls_ctx_create -- create an SSL_CTX for a client.
 *
 * ca_cert : path to PEM CA certificate to verify the server, or NULL to skip
 *           server certificate verification.
 * cert    : path to client certificate PEM, or NULL for no mutual TLS.
 * key     : path to client private key PEM, or NULL for no mutual TLS.
 *
 * Returns an SSL_CTX on success, NULL on error (OpenSSL errors logged to
 * stderr).
 */
SSL_CTX *tls_ctx_create(const char *ca_cert, const char *cert,
                        const char *key);

/*
 * tls_connect_starttls -- connect to host:port, perform RFC 9289 STARTTLS.
 *
 * Sends a NULL RPC call with AUTH_TLS credential, reads the reply, then
 * upgrades the connection with SSL_connect().  Verifies ALPN = "sunrpc".
 *
 * host    : hostname or IP address string
 * port    : port number string (e.g. "2049")
 * ctx     : SSL_CTX from tls_ctx_create()
 * conn    : output; filled in on success
 * errbuf  : caller-allocated buffer for error message
 * errsz   : size of errbuf
 *
 * Returns 0 on success, -1 on error (errbuf filled).
 */
int tls_connect_starttls(const char *host, const char *port,
                         SSL_CTX *ctx, struct tls_conn *conn,
                         char *errbuf, size_t errsz);

/*
 * tls_send_nfs_null -- send a NULL RPC call over TLS and verify the reply.
 *
 * Used to confirm the TLS session is functional for NFS traffic.
 *
 * Returns 0 on success, -1 on error (errbuf filled).
 */
int tls_send_nfs_null(struct tls_conn *conn, char *errbuf, size_t errsz);

/*
 * tls_conn_close -- close the SSL connection and underlying TCP socket.
 *
 * Sends TLS close_notify.  conn->tc_ssl and conn->tc_fd are released.
 * The SSL_CTX (tc_ctx) is not freed here.
 */
void tls_conn_close(struct tls_conn *conn);

#endif /* TLS_CLIENT_H */
