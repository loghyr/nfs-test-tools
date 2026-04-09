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
 *   5. Optionally send post-TLS NULL RPC calls to confirm the session works.
 */

#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <stddef.h>
#include <stdint.h>
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
 * struct tls_timing -- per-phase latency breakdown for one connection.
 *
 * All values are in milliseconds measured via CLOCK_MONOTONIC.
 * Passed as an optional output parameter to tls_connect_starttls();
 * pass NULL to skip recording.
 */
struct tls_timing {
    double tt_tcp_ms;       /* TCP connect() round-trip */
    double tt_probe_ms;     /* AUTH_TLS probe send + reply receive */
    double tt_handshake_ms; /* SSL_connect() */
};

/*
 * tls_ctx_create -- create an SSL_CTX for a client.
 *
 * The returned context disables the internal session cache
 * (SSL_SESS_CACHE_OFF) so that session reuse is managed explicitly by
 * the caller via tls_connect_starttls(session_in) and
 * tls_conn_get_session().
 *
 * ca_cert : path to PEM CA certificate to verify the server, or NULL to skip
 *           server certificate verification.
 * cert    : path to client certificate PEM, or NULL for no mutual TLS.
 * key     : path to client private key PEM, or NULL for no mutual TLS.
 *
 * Returns an SSL_CTX on success, NULL on error (errors logged to stderr).
 */
SSL_CTX *tls_ctx_create(const char *ca_cert, const char *cert,
                        const char *key);

/*
 * tls_connect_starttls -- connect to host:port, perform RFC 9289 STARTTLS.
 *
 * Sends a NULL RPC call with AUTH_TLS credential, reads the reply, then
 * upgrades the connection with SSL_connect().  Verifies ALPN = "sunrpc".
 *
 * host       : hostname or IP address string
 * port       : port number string (e.g. "2049")
 * ctx        : SSL_CTX from tls_ctx_create()
 * session_in : prior SSL_SESSION for resumption, or NULL for a full handshake.
 *              The caller retains ownership; this function calls
 *              SSL_set_session() (which takes its own reference) and does
 *              NOT free session_in.
 * conn       : output; filled in on success
 * xid        : XID for the AUTH_TLS probe RPC call
 * timing     : output for per-phase latencies, or NULL to skip
 * errbuf     : caller-allocated buffer for error message
 * errsz      : size of errbuf
 *
 * Returns 0 on success, -1 on error (errbuf filled).
 */
int tls_connect_starttls(const char *host, const char *port,
                         SSL_CTX *ctx,
                         SSL_SESSION *session_in,
                         struct tls_conn *conn,
                         uint32_t xid,
                         struct tls_timing *timing,
                         char *errbuf, size_t errsz);

/*
 * tls_send_nfs_null -- send a NULL RPC call over TLS and verify the reply.
 *
 * xid    : XID to use for this RPC call (caller increments per call)
 *
 * Returns 0 on success, -1 on error (errbuf filled).
 */
int tls_send_nfs_null(struct tls_conn *conn, uint32_t xid,
                      char *errbuf, size_t errsz);

/*
 * tls_conn_get_session -- retrieve the negotiated TLS session for reuse.
 *
 * Returns a new reference to the SSL_SESSION (caller must call
 * SSL_SESSION_free() when done).  Returns NULL if no session is available
 * (e.g., session ticket not yet received in TLS 1.3).
 *
 * Call after tls_send_nfs_null() to allow TLS 1.3 session tickets to
 * arrive via the post-handshake read.
 */
SSL_SESSION *tls_conn_get_session(struct tls_conn *conn);

/*
 * tls_conn_print_info -- print negotiated TLS version, cipher, and key
 * exchange group to stdout.  Call after a successful tls_connect_starttls().
 */
void tls_conn_print_info(const struct tls_conn *conn);

/*
 * tls_conn_close -- close the SSL connection and underlying TCP socket.
 *
 * Sends TLS close_notify.  conn->tc_ssl and conn->tc_fd are released.
 * The SSL_CTX (tc_ctx) is not freed here.
 */
void tls_conn_close(struct tls_conn *conn);

#endif /* TLS_CLIENT_H */
