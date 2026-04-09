/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tls_client.c -- RFC 9289 STARTTLS client implementation.
 *
 * Protocol flow per RFC 9289 S4.1:
 *   1. TCP connect
 *   2. Client sends NULL RPC call with cred.flavor = AUTH_TLS (7),
 *      cred.len = 0 (NFS prog=100003, vers=4, proc=0)
 *   3. Server replies with RPC_SUCCESS; reply has AUTH_NONE verifier
 *      (an AUTH_TLS verifier would indicate a version mismatch)
 *   4. Both sides perform TLS handshake with ALPN "sunrpc"
 *   5. Connection is now RPC-over-TLS
 */

#include "tls_client.h"
#include "rpc_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/err.h>

/* Maximum RPC reply body we will accept during STARTTLS (before TLS) */
#define STARTTLS_REPLY_MAX 512

/* --- internal helpers --- */

/*
 * ssl_readn -- read exactly n bytes from ssl, retrying on EINTR.
 * Returns n on success, 0 on EOF, -1 on error.
 */
static ssize_t ssl_readn(SSL *ssl, void *buf, size_t n)
{
    size_t got = 0;
    uint8_t *p = (uint8_t *)buf;
    while (got < n) {
        int r = SSL_read(ssl, p + got, (int)(n - got));
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN)
                return 0;  /* clean EOF */
            return -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)n;
}

/*
 * ssl_writen -- write exactly n bytes to ssl.
 * Returns n on success, -1 on error.
 */
static ssize_t ssl_writen(SSL *ssl, const void *buf, size_t n)
{
    size_t sent = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (sent < n) {
        int r = SSL_write(ssl, p + sent, (int)(n - sent));
        if (r <= 0)
            return -1;
        sent += (size_t)r;
    }
    return (ssize_t)n;
}

/*
 * ossl_errbuf -- append last OpenSSL error string to errbuf.
 */
static void ossl_errbuf(char *errbuf, size_t errsz, const char *prefix)
{
    char ossl[256];
    unsigned long e = ERR_get_error();
    if (e)
        ERR_error_string_n(e, ossl, sizeof(ossl));
    else
        snprintf(ossl, sizeof(ossl), "(no OpenSSL error)");
    snprintf(errbuf, errsz, "%s: %s", prefix, ossl);
}

/*
 * tcp_connect -- resolve host:port and return a connected TCP socket.
 * Returns fd >= 0 on success, -1 on error (errbuf filled).
 */
static int tcp_connect(const char *host, const char *port,
                       char *errbuf, size_t errsz)
{
    struct addrinfo hints, *res, *r;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        snprintf(errbuf, errsz, "getaddrinfo(%s:%s): %s",
                 host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (r = res; r != NULL; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        snprintf(errbuf, errsz, "connect(%s:%s): %s",
                 host, port, strerror(errno));
        return -1;
    }
    return fd;
}

/*
 * send_auth_tls_probe -- send the RFC 9289 AUTH_TLS NULL call.
 * Returns 0 on success, -1 on error (errbuf filled).
 */
static int send_auth_tls_probe(int fd, uint32_t xid,
                               char *errbuf, size_t errsz)
{
    uint8_t buf[64];
    size_t len = rpc_build_null_call(buf, sizeof(buf), xid,
                                      NFS_PROGRAM, NFS_VERSION_4,
                                      RPC_AUTH_TLS);
    if (len == 0) {
        snprintf(errbuf, errsz, "rpc_build_null_call: buffer too small");
        return -1;
    }
    if (rpc_writen(fd, buf, len) != (ssize_t)len) {
        snprintf(errbuf, errsz, "write AUTH_TLS probe: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * recv_starttls_reply -- read the AUTH_TLS probe reply and verify RPC_SUCCESS.
 *
 * The reply format is:
 *   [4-byte TCP record marker]
 *   [xid][REPLY=1][MSG_ACCEPTED=0][verf.flavor][verf.len][body...]
 *   [accept_stat=SUCCESS=0]
 *
 * RFC 9289 S4.1: the server's reply verifier SHOULD be AUTH_NONE (0,0)
 * to indicate it supports the same TLS version as the client.  We accept
 * any verifier flavor and skip its body before reading accept_stat.
 *
 * Returns 0 on success, -1 on error (errbuf filled).
 */
static int recv_starttls_reply(int fd, uint32_t expected_xid,
                               char *errbuf, size_t errsz)
{
    /* Read 4-byte record marker */
    uint8_t marker_buf[4];
    if (rpc_readn(fd, marker_buf, 4) != 4) {
        snprintf(errbuf, errsz, "read record marker: %s",
                 errno ? strerror(errno) : "EOF");
        return -1;
    }
    size_t mpos = 0;
    uint32_t marker;
    rpc_get_u32(marker_buf, 4, &mpos, &marker);

    if (!(marker & RPC_LAST_FRAG)) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: multi-fragment reply not expected");
        return -1;
    }
    uint32_t body_len = marker & ~RPC_LAST_FRAG;
    if (body_len == 0 || body_len > STARTTLS_REPLY_MAX) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: implausible body length %u", body_len);
        return -1;
    }

    uint8_t body[STARTTLS_REPLY_MAX];
    if (rpc_readn(fd, body, body_len) != (ssize_t)body_len) {
        snprintf(errbuf, errsz, "read STARTTLS reply body: %s",
                 errno ? strerror(errno) : "EOF");
        return -1;
    }

    size_t pos = 0;
    uint32_t xid, msg_type, reply_stat, verf_flavor, verf_len, accept_stat;

    if (!rpc_get_u32(body, body_len, &pos, &xid) ||
        !rpc_get_u32(body, body_len, &pos, &msg_type) ||
        !rpc_get_u32(body, body_len, &pos, &reply_stat)) {
        snprintf(errbuf, errsz, "STARTTLS reply: short header");
        return -1;
    }

    if (xid != expected_xid) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: xid mismatch (got %u, want %u)",
                 xid, expected_xid);
        return -1;
    }
    if (msg_type != RPC_REPLY) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: expected REPLY (1), got %u", msg_type);
        return -1;
    }
    if (reply_stat != RPC_MSG_ACCEPTED) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: MSG_DENIED (%u) -- server rejected TLS probe",
                 reply_stat);
        return -1;
    }

    /* Read verifier (flavor + length), then skip the body */
    if (!rpc_get_u32(body, body_len, &pos, &verf_flavor) ||
        !rpc_get_u32(body, body_len, &pos, &verf_len)) {
        snprintf(errbuf, errsz, "STARTTLS reply: short verifier header");
        return -1;
    }
    /* Skip verf body, padded to 4-byte alignment */
    uint32_t verf_padded = (verf_len + 3u) & ~3u;
    if (!rpc_skip(body_len, &pos, verf_padded)) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: verifier body truncated (len=%u)", verf_len);
        return -1;
    }

    if (!rpc_get_u32(body, body_len, &pos, &accept_stat)) {
        snprintf(errbuf, errsz, "STARTTLS reply: no accept_stat");
        return -1;
    }
    if (accept_stat != RPC_SUCCESS) {
        snprintf(errbuf, errsz,
                 "STARTTLS reply: accept_stat %u (not SUCCESS)", accept_stat);
        return -1;
    }
    return 0;
}

/* --- public API --- */

SSL_CTX *tls_ctx_create(const char *ca_cert, const char *cert, const char *key)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Minimum TLS 1.3 per RFC 9289 S4 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (ca_cert) {
        if (!SSL_CTX_load_verify_locations(ctx, ca_cert, NULL)) {
            fprintf(stderr, "SSL_CTX_load_verify_locations(%s) failed\n",
                    ca_cert);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        /* Skip server certificate verification -- useful for testing */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    if (cert && key) {
        if (!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) ||
            !SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) {
            fprintf(stderr, "Failed to load client cert/key\n");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

int tls_connect_starttls(const char *host, const char *port,
                         SSL_CTX *ctx, struct tls_conn *conn,
                         char *errbuf, size_t errsz)
{
    memset(conn, 0, sizeof(*conn));
    conn->tc_fd  = -1;
    conn->tc_ctx = ctx;

    /* Step 1: TCP connect */
    conn->tc_fd = tcp_connect(host, port, errbuf, errsz);
    if (conn->tc_fd < 0)
        return -1;

    /* Step 2: Send AUTH_TLS NULL probe */
    uint32_t xid = (uint32_t)getpid() ^ (uint32_t)(uintptr_t)conn;
    if (send_auth_tls_probe(conn->tc_fd, xid, errbuf, errsz) < 0) {
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    /* Step 3: Read and verify RPC_SUCCESS reply */
    if (recv_starttls_reply(conn->tc_fd, xid, errbuf, errsz) < 0) {
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    /* Step 4: TLS handshake */
    conn->tc_ssl = SSL_new(ctx);
    if (!conn->tc_ssl) {
        ossl_errbuf(errbuf, errsz, "SSL_new");
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    /* ALPN: wire encoding is length-prefixed ("sunrpc" = 6 bytes) */
    static const uint8_t alpn_sunrpc[] = { 6, 's', 'u', 'n', 'r', 'p', 'c' };
    if (SSL_set_alpn_protos(conn->tc_ssl, alpn_sunrpc, sizeof(alpn_sunrpc))) {
        /* returns 0 on success, non-zero on error (OpenSSL API oddity) */
        ossl_errbuf(errbuf, errsz, "SSL_set_alpn_protos");
        SSL_free(conn->tc_ssl);
        conn->tc_ssl = NULL;
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    if (!SSL_set_fd(conn->tc_ssl, conn->tc_fd)) {
        ossl_errbuf(errbuf, errsz, "SSL_set_fd");
        SSL_free(conn->tc_ssl);
        conn->tc_ssl = NULL;
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    if (SSL_connect(conn->tc_ssl) != 1) {
        ossl_errbuf(errbuf, errsz, "SSL_connect");
        SSL_free(conn->tc_ssl);
        conn->tc_ssl = NULL;
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    /* Step 5: Verify ALPN negotiated to "sunrpc" (RFC 9289 S4.1) */
    const uint8_t *proto;
    unsigned int   proto_len;
    SSL_get0_alpn_selected(conn->tc_ssl, &proto, &proto_len);
    if (proto_len != 6 || memcmp(proto, "sunrpc", 6) != 0) {
        snprintf(errbuf, errsz,
                 "TLS ALPN mismatch: server negotiated '%.*s', want 'sunrpc'",
                 (int)proto_len, proto ? (const char *)proto : "");
        SSL_free(conn->tc_ssl);
        conn->tc_ssl = NULL;
        close(conn->tc_fd);
        conn->tc_fd = -1;
        return -1;
    }

    return 0;
}

int tls_send_nfs_null(struct tls_conn *conn, char *errbuf, size_t errsz)
{
    /* Send a NULL RPC call over TLS -- AUTH_NONE, NFS prog/vers */
    uint8_t call_buf[64];
    uint32_t xid = (uint32_t)getpid() ^ 0xbeef0000u;
    size_t call_len = rpc_build_null_call(call_buf, sizeof(call_buf), xid,
                                           NFS_PROGRAM, NFS_VERSION_4,
                                           RPC_AUTH_NONE);
    if (call_len == 0) {
        snprintf(errbuf, errsz, "rpc_build_null_call: buffer too small");
        return -1;
    }
    if (ssl_writen(conn->tc_ssl, call_buf, call_len) != (ssize_t)call_len) {
        ossl_errbuf(errbuf, errsz, "SSL_write NULL call");
        return -1;
    }

    /* Read record marker via TLS */
    uint8_t marker_buf[4];
    if (ssl_readn(conn->tc_ssl, marker_buf, 4) != 4) {
        snprintf(errbuf, errsz, "SSL_read record marker: %s",
                 errno ? strerror(errno) : "EOF");
        return -1;
    }
    size_t mpos = 0;
    uint32_t marker;
    rpc_get_u32(marker_buf, 4, &mpos, &marker);
    if (!(marker & RPC_LAST_FRAG)) {
        snprintf(errbuf, errsz, "NULL reply: multi-fragment reply unexpected");
        return -1;
    }
    uint32_t body_len = marker & ~RPC_LAST_FRAG;
    if (body_len == 0 || body_len > STARTTLS_REPLY_MAX) {
        snprintf(errbuf, errsz, "NULL reply: implausible body length %u",
                 body_len);
        return -1;
    }

    uint8_t body[STARTTLS_REPLY_MAX];
    if (ssl_readn(conn->tc_ssl, body, body_len) != (ssize_t)body_len) {
        snprintf(errbuf, errsz, "SSL_read NULL reply body: %s",
                 errno ? strerror(errno) : "EOF");
        return -1;
    }

    size_t pos = 0;
    uint32_t rxid, msg_type, reply_stat, verf_flavor, verf_len, accept_stat;

    if (!rpc_get_u32(body, body_len, &pos, &rxid) ||
        !rpc_get_u32(body, body_len, &pos, &msg_type) ||
        !rpc_get_u32(body, body_len, &pos, &reply_stat) ||
        !rpc_get_u32(body, body_len, &pos, &verf_flavor) ||
        !rpc_get_u32(body, body_len, &pos, &verf_len)) {
        snprintf(errbuf, errsz, "NULL reply: short header");
        return -1;
    }
    uint32_t verf_padded = (verf_len + 3u) & ~3u;
    if (!rpc_skip(body_len, &pos, verf_padded) ||
        !rpc_get_u32(body, body_len, &pos, &accept_stat)) {
        snprintf(errbuf, errsz, "NULL reply: truncated body");
        return -1;
    }

    if (rxid != xid) {
        snprintf(errbuf, errsz, "NULL reply: xid mismatch (got %u, want %u)",
                 rxid, xid);
        return -1;
    }
    if (msg_type != RPC_REPLY || reply_stat != RPC_MSG_ACCEPTED ||
        accept_stat != RPC_SUCCESS) {
        snprintf(errbuf, errsz,
                 "NULL reply: unexpected status msg=%u reply=%u accept=%u",
                 msg_type, reply_stat, accept_stat);
        return -1;
    }
    return 0;
}

void tls_conn_close(struct tls_conn *conn)
{
    if (conn->tc_ssl) {
        SSL_shutdown(conn->tc_ssl);
        SSL_free(conn->tc_ssl);
        conn->tc_ssl = NULL;
    }
    if (conn->tc_fd >= 0) {
        close(conn->tc_fd);
        conn->tc_fd = -1;
    }
}
