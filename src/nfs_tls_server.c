/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_tls_server.c -- minimal RFC 9289 STARTTLS server for testing clients.
 *
 * Listens on a TCP port (default 2049) and acts as the server side of
 * RFC 9289 RPC-over-TLS:
 *   1. Accept TCP connection
 *   2. Read the AUTH_TLS NULL probe call
 *   3. Reply with RPC_SUCCESS (AUTH_NONE verifier)
 *   4. Perform server-side TLS handshake with ALPN "sunrpc"
 *   5. Read NULL RPC calls over the TLS channel and reply
 *
 * This is the mirror of nfs_tls_test on the server side: instead of
 * driving connections at a server, it accepts connections from a client
 * being tested.  Useful for verifying RFC 9289 client implementations
 * (knfsd's tlshd, FreeBSD's rpc.tlsclntd, custom user-space clients,
 * etc.) without needing a full NFS server stack.
 *
 * Single-threaded by design: handles one client at a time.  This is
 * intentional -- it makes the server trivially debuggable and avoids
 * concurrency complexity in a tool whose job is to expose protocol
 * conformance bugs.
 *
 * Usage:
 *   nfs_tls_server --cert FILE --key FILE [options]
 *
 * Options:
 *   --port PORT         Listen port (default: 2049)
 *   --cert FILE         Server certificate PEM (required)
 *   --key  FILE         Server private key PEM (required)
 *   --ca-cert FILE      CA bundle for client verification (mutual TLS)
 *   --require-mtls      Require client to present a cert (default: optional)
 *   --max-conns N       Exit after N connections (default: 0 = unlimited)
 *   --verbose           Print per-connection wire details
 *   --keylog FILE       Write NSS-format TLS key log
 */

#include "rpc_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define NULL_REPLY_MAX 64
#define INCOMING_MAX  4096

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* --- shared keylog support (mirror of tls_client.c) --- */

static FILE *g_keylog_fp = NULL;
static void keylog_callback(const SSL *ssl, const char *line)
{
    (void)ssl;
    if (g_keylog_fp) {
        fputs(line, g_keylog_fp);
        fputc('\n', g_keylog_fp);
        fflush(g_keylog_fp);
    }
}

/*
 * rpc_build_null_reply -- encode a successful NULL RPC reply.
 *
 * [4-byte record marker (LAST_FRAG | body_len)]
 * [xid] [REPLY=1] [MSG_ACCEPTED=0]
 * [verf.flavor=AUTH_NONE] [verf.len=0]
 * [accept_stat=SUCCESS=0]
 *
 * Total body = 6 * 4 = 24 bytes; total wire = 28 bytes.
 *
 * Returns the wire size on success, 0 on overflow.
 */
static size_t build_null_reply(uint8_t *buf, size_t bufsz, uint32_t xid)
{
    const uint32_t body_len = 24;
    size_t pos = 0;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_LAST_FRAG | body_len)) return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, xid))                       return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_REPLY))                 return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_MSG_ACCEPTED))          return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_AUTH_NONE))             return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, 0u))                        return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_SUCCESS))               return 0;
    return pos;  /* 28 */
}

/*
 * Read one RPC record from a plain fd.  Returns body length and fills
 * out body[].  Returns 0 on EOF, -1 on error.
 */
static int read_rpc_record_fd(int fd, uint8_t *body, size_t bodysz,
                              uint32_t *body_len_out)
{
    uint8_t marker_buf[4];
    ssize_t r = rpc_readn(fd, marker_buf, 4);
    if (r == 0) return 0;
    if (r != 4) return -1;

    size_t mpos = 0;
    uint32_t marker;
    rpc_get_u32(marker_buf, 4, &mpos, &marker);
    if (!(marker & RPC_LAST_FRAG)) return -1;
    uint32_t body_len = marker & ~RPC_LAST_FRAG;
    if (body_len == 0 || body_len > bodysz) return -1;

    if (rpc_readn(fd, body, body_len) != (ssize_t)body_len) return -1;
    *body_len_out = body_len;
    return 1;
}

/*
 * Read one RPC record from an SSL connection.  Same return contract.
 */
static int read_rpc_record_ssl(SSL *ssl, uint8_t *body, size_t bodysz,
                               uint32_t *body_len_out)
{
    uint8_t marker_buf[4];
    int n = SSL_read(ssl, marker_buf, 4);
    if (n == 0) return 0;
    if (n != 4) return -1;

    size_t mpos = 0;
    uint32_t marker;
    rpc_get_u32(marker_buf, 4, &mpos, &marker);
    if (!(marker & RPC_LAST_FRAG)) return -1;
    uint32_t body_len = marker & ~RPC_LAST_FRAG;
    if (body_len == 0 || body_len > bodysz) return -1;

    int got = 0;
    while (got < (int)body_len) {
        int r = SSL_read(ssl, body + got, (int)body_len - got);
        if (r <= 0) return -1;
        got += r;
    }
    *body_len_out = body_len;
    return 1;
}

/*
 * Parse an RPC call header.  Sets *xid_out, *cred_flavor_out.  Returns
 * 1 on success, 0 if the body is malformed.
 */
static int parse_rpc_call(const uint8_t *body, size_t body_len,
                          uint32_t *xid_out, uint32_t *cred_flavor_out)
{
    size_t pos = 0;
    uint32_t xid, msg_type, rpcvers, prog, vers, proc;
    uint32_t cred_flavor, cred_len, verf_flavor, verf_len;

    if (!rpc_get_u32(body, body_len, &pos, &xid) ||
        !rpc_get_u32(body, body_len, &pos, &msg_type) ||
        !rpc_get_u32(body, body_len, &pos, &rpcvers) ||
        !rpc_get_u32(body, body_len, &pos, &prog) ||
        !rpc_get_u32(body, body_len, &pos, &vers) ||
        !rpc_get_u32(body, body_len, &pos, &proc) ||
        !rpc_get_u32(body, body_len, &pos, &cred_flavor) ||
        !rpc_get_u32(body, body_len, &pos, &cred_len))
        return 0;

    /* Skip credential body */
    uint32_t cred_padded = (cred_len + 3u) & ~3u;
    if (!rpc_skip(body_len, &pos, cred_padded)) return 0;

    if (!rpc_get_u32(body, body_len, &pos, &verf_flavor) ||
        !rpc_get_u32(body, body_len, &pos, &verf_len))
        return 0;

    if (msg_type != RPC_CALL || rpcvers != 2)
        return 0;

    *xid_out = xid;
    *cred_flavor_out = cred_flavor;
    return 1;
}

/* --- TLS server context --- */

static SSL_CTX *create_server_ctx(const char *cert, const char *key,
                                  const char *ca_cert, int require_mtls)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "load server cert/key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "server cert and key do not match\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (ca_cert) {
        if (!SSL_CTX_load_verify_locations(ctx, ca_cert, NULL)) {
            fprintf(stderr, "load CA cert failed\n");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        int mode = SSL_VERIFY_PEER;
        if (require_mtls)
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(ctx, mode, NULL);
    }

    return ctx;
}

/*
 * ALPN selection callback: pick "sunrpc" if the client offered it,
 * otherwise reject.
 */
static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen,
                          void *arg)
{
    (void)ssl; (void)arg;
    /* Walk the protocol list looking for "sunrpc" */
    unsigned int i = 0;
    while (i < inlen) {
        unsigned char plen = in[i];
        if (i + 1 + plen > inlen) break;
        if (plen == 6 && memcmp(in + i + 1, "sunrpc", 6) == 0) {
            *out = in + i + 1;
            *outlen = plen;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + plen;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* --- per-connection state machine --- */

struct conn_stats {
    int verbose;
    long total_conns;
    long ok_conns;
    long fail_starttls;
    long fail_handshake;
    long fail_alpn;
    long total_nulls;
};

static void handle_one(int cfd, SSL_CTX *ctx, struct conn_stats *stats,
                       struct sockaddr_in *peer)
{
    char ipbuf[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &peer->sin_addr, ipbuf, sizeof(ipbuf));

    stats->total_conns++;
    if (stats->verbose)
        printf("[%ld] connect from %s:%u\n",
               stats->total_conns, ipbuf, ntohs(peer->sin_port));

    /* Read AUTH_TLS NULL probe */
    uint8_t body[INCOMING_MAX];
    uint32_t body_len;
    int rc = read_rpc_record_fd(cfd, body, sizeof(body), &body_len);
    if (rc <= 0) {
        if (stats->verbose)
            printf("  STARTTLS read failed: %s\n",
                   rc == 0 ? "EOF" : strerror(errno));
        stats->fail_starttls++;
        return;
    }

    uint32_t xid, cred_flavor;
    if (!parse_rpc_call(body, body_len, &xid, &cred_flavor)) {
        if (stats->verbose)
            printf("  STARTTLS: malformed call\n");
        stats->fail_starttls++;
        return;
    }

    if (cred_flavor != RPC_AUTH_TLS) {
        if (stats->verbose)
            printf("  STARTTLS: cred flavor %u (not AUTH_TLS=7)\n",
                   cred_flavor);
        /* Still send a reply, just to be polite */
        stats->fail_starttls++;
        return;
    }

    /* Send the STARTTLS reply (NULL_RESPONSE with AUTH_NONE verifier) */
    uint8_t reply[NULL_REPLY_MAX];
    size_t reply_len = build_null_reply(reply, sizeof(reply), xid);
    if (rpc_writen(cfd, reply, reply_len) != (ssize_t)reply_len) {
        if (stats->verbose)
            printf("  STARTTLS reply write failed: %s\n", strerror(errno));
        stats->fail_starttls++;
        return;
    }
    if (stats->verbose)
        printf("  STARTTLS probe accepted (xid=%u)\n", xid);

    /* TLS handshake */
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        stats->fail_handshake++;
        return;
    }
    SSL_set_fd(ssl, cfd);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

    if (SSL_accept(ssl) != 1) {
        if (stats->verbose) {
            unsigned long e = ERR_get_error();
            char buf[256];
            ERR_error_string_n(e, buf, sizeof(buf));
            printf("  TLS handshake failed: %s\n", buf);
        }
        stats->fail_handshake++;
        SSL_free(ssl);
        return;
    }

    /* Verify ALPN landed on "sunrpc" */
    const unsigned char *proto = NULL;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);
    if (!proto || proto_len != 6 || memcmp(proto, "sunrpc", 6) != 0) {
        if (stats->verbose)
            printf("  ALPN missing or not 'sunrpc'\n");
        stats->fail_alpn++;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    if (stats->verbose) {
        const char *ver = SSL_get_version(ssl);
        const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
        printf("  TLS up: %s, %s, ALPN=sunrpc\n",
               ver, c ? SSL_CIPHER_get_name(c) : "?");
    }

    stats->ok_conns++;

    /* Service NULL RPCs over TLS until the client closes */
    for (;;) {
        rc = read_rpc_record_ssl(ssl, body, sizeof(body), &body_len);
        if (rc <= 0)
            break;

        uint32_t rxid, rcred;
        if (!parse_rpc_call(body, body_len, &rxid, &rcred)) {
            if (stats->verbose)
                printf("  malformed call over TLS\n");
            break;
        }

        size_t rl = build_null_reply(reply, sizeof(reply), rxid);
        if (SSL_write(ssl, reply, (int)rl) != (int)rl)
            break;

        stats->total_nulls++;
        if (stats->verbose)
            printf("  NULL reply sent (xid=%u)\n", rxid);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/* --- main --- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --cert FILE --key FILE [options]\n"
        "\n"
        "Options:\n"
        "  --port PORT         Listen port (default: 2049)\n"
        "  --cert FILE         Server certificate PEM (required)\n"
        "  --key FILE          Server private key PEM (required)\n"
        "  --ca-cert FILE      CA bundle for client verification\n"
        "  --require-mtls      Require client to present a certificate\n"
        "  --max-conns N       Exit after N connections (default: unlimited)\n"
        "  --verbose           Print per-connection wire details\n"
        "  --keylog FILE       Write NSS-format TLS key log\n"
        "\n"
        "Minimal RFC 9289 STARTTLS server for testing client implementations.\n"
        "Listens for AUTH_TLS NULL probes, performs the TLS handshake with\n"
        "ALPN 'sunrpc', and replies to NULL RPCs over the encrypted channel.\n"
        "Single-threaded; one client at a time.\n",
        prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "port",         required_argument, NULL, 'p' },
        { "cert",         required_argument, NULL, 'c' },
        { "key",          required_argument, NULL, 'k' },
        { "ca-cert",      required_argument, NULL, 'C' },
        { "require-mtls", no_argument,       NULL, 'M' },
        { "max-conns",    required_argument, NULL, 'm' },
        { "verbose",      no_argument,       NULL, 'v' },
        { "keylog",       required_argument, NULL, 'L' },
        { NULL, 0, NULL, 0 }
    };

    int port = 2049;
    const char *cert = NULL, *key = NULL, *ca_cert = NULL;
    int require_mtls = 0;
    long max_conns = 0;
    int verbose = 0;
    const char *keylog = NULL;

    int ch;
    while ((ch = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'p': port         = atoi(optarg); break;
        case 'c': cert         = optarg;       break;
        case 'k': key          = optarg;       break;
        case 'C': ca_cert      = optarg;       break;
        case 'M': require_mtls = 1;            break;
        case 'm': max_conns    = atol(optarg); break;
        case 'v': verbose      = 1;            break;
        case 'L': keylog       = optarg;       break;
        default:  usage(argv[0]);
        }
    }
    if (!cert || !key)
        usage(argv[0]);

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_server_ctx(cert, key, ca_cert, require_mtls);
    if (!ctx) return EXIT_FAILURE;

    if (keylog) {
        g_keylog_fp = fopen(keylog, "ae");
        if (!g_keylog_fp) {
            fprintf(stderr, "fopen(%s): %s\n", keylog, strerror(errno));
            SSL_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        SSL_CTX_set_keylog_callback(ctx, keylog_callback);
        printf("TLS keylog: %s\n", keylog);
    }

    /* Listen socket */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(lfd);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    if (listen(lfd, 16) < 0) {
        perror("listen");
        close(lfd);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    printf("nfs_tls_server listening on port %d "
           "(cert=%s, mtls=%s%s)\n",
           port, cert,
           ca_cert ? (require_mtls ? "required" : "optional") : "off",
           keylog ? ", keylog enabled" : "");

    struct conn_stats stats = {0};
    stats.verbose = verbose;

    while (!g_stop) {
        if (max_conns > 0 && stats.total_conns >= max_conns)
            break;

        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        handle_one(cfd, ctx, &stats, &peer);
        close(cfd);
    }

    close(lfd);
    if (g_keylog_fp)
        fclose(g_keylog_fp);
    SSL_CTX_free(ctx);

    printf("\nServer stats:\n");
    printf("  total connections: %ld\n", stats.total_conns);
    printf("  successful TLS:    %ld\n", stats.ok_conns);
    printf("  STARTTLS failures: %ld\n", stats.fail_starttls);
    printf("  handshake failures:%ld\n", stats.fail_handshake);
    printf("  ALPN failures:     %ld\n", stats.fail_alpn);
    printf("  NULL RPCs served:  %ld\n", stats.total_nulls);

    return EXIT_SUCCESS;
}
