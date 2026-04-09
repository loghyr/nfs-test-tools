/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_krb5_test.c -- RPCSEC_GSS / Kerberos 5 authentication tester.
 *
 * Connects to an NFS server over TCP, establishes an RPCSEC_GSS context
 * (RFC 2203 S5), and sends a DATA NULL call with a GSS MIC verifier.
 * Verifies the server's reply verifier.
 *
 * This exercises the full Kerberos authentication path:
 *   1. gss_import_name for the NFS service principal
 *   2. RPCSEC_GSS INIT / CONTINUE_INIT exchange
 *   3. DATA NULL call with gss_get_mic() verifier
 *   4. Reply verifier check with gss_verify_mic()
 *
 * Usage:
 *   nfs_krb5_test --host SERVER [options]
 *
 * Options:
 *   --host HOST         NFS server hostname or IP (required)
 *   --port PORT         Port number (default: 2049)
 *   --principal NAME    Service principal (default: nfs@HOST)
 *   --iterations N      Number of NULL calls after context setup (default: 1)
 *   --verbose           Print GSS token exchange details
 */

#include "rpc_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

/* Maximum GSS token size we handle */
#define GSS_TOKEN_MAX   65536
/* Maximum RPC message we handle */
#define RPC_MSG_MAX     (GSS_TOKEN_MAX + 1024)

/* -----------------------------------------------------------------------
 * RPCSEC_GSS constants (RFC 2203)
 * --------------------------------------------------------------------- */

/* RPCSEC_GSS version */
#define RPCSEC_GSS_VERSION  1u

/* -----------------------------------------------------------------------
 * GSS context state
 * --------------------------------------------------------------------- */

struct gss_ctx {
    gss_ctx_id_t  gc_ctx;       /* GSS context handle */
    gss_name_t    gc_svc_name;  /* target service name */
    gss_OID       gc_mech;      /* negotiated mech (krb5) */
    uint32_t      gc_handle_len;
    uint8_t       gc_handle[256]; /* RPCSEC_GSS context handle from server */
    uint32_t      gc_seq_num;   /* last sequence number used for DATA */
};

/* -----------------------------------------------------------------------
 * TCP helpers (duplicate from tls_client.c to keep the file standalone)
 * --------------------------------------------------------------------- */

static int tcp_connect_host(const char *host, const char *port,
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
    for (r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
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

/* -----------------------------------------------------------------------
 * RPC message builder for RPCSEC_GSS
 *
 * RPCSEC_GSS credential structure (RFC 2203 S5):
 *   version    : uint32 = 1
 *   gss_proc   : uint32 (RPCSEC_GSS_INIT / DATA / ...)
 *   seq_num    : uint32
 *   service    : uint32 (rpc_gss_svc_none / integ / priv)
 *   handle     : opaque<>  (empty on INIT; server-assigned on DATA)
 *
 * Verifier for DATA calls: gss_get_mic() over call header bytes
 *   (xid through end of credential, inclusive).
 * --------------------------------------------------------------------- */

/*
 * rpc_put_opaque -- append an XDR opaque<> (4-byte length + data + padding).
 */
static int rpc_put_opaque(uint8_t *buf, size_t bufsz, size_t *pos,
                           const uint8_t *data, uint32_t len)
{
    if (!rpc_put_u32(buf, bufsz, pos, len))
        return 0;
    if (*pos + len > bufsz)
        return 0;
    memcpy(buf + *pos, data, len);
    *pos += len;
    /* XDR padding to 4-byte boundary */
    uint32_t pad = (4 - (len & 3)) & 3;
    if (pad) {
        if (*pos + pad > bufsz)
            return 0;
        memset(buf + *pos, 0, pad);
        *pos += pad;
    }
    return 1;
}

/*
 * build_gss_init_call -- build an RPCSEC_GSS INIT or CONTINUE_INIT call.
 *
 * The GSS INIT call carries the outgoing GSS token as the procedure body.
 * There is no verifier on INIT (AUTH_NONE verifier).
 *
 * Returns total byte count, or 0 on error.
 */
static size_t build_gss_init_call(uint8_t *buf, size_t bufsz,
                                   uint32_t xid, uint32_t prog, uint32_t vers,
                                   uint32_t gss_proc,
                                   const uint8_t *handle, uint32_t handle_len,
                                   const gss_buffer_t token)
{
    /* We need to know the credential length before writing the header.
     * Credential body:
     *   version(4) + gss_proc(4) + seq_num(4) + service(4)
     *   + handle_len(4) + handle + padding
     */
    uint32_t handle_padded = (handle_len + 3u) & ~3u;
    uint32_t cred_body_len = 4 + 4 + 4 + 4 + 4 + handle_padded;

    size_t pos = 0;

    /* Record marker: placeholder -- we fill it after we know total len */
    size_t marker_pos = pos;
    if (!rpc_put_u32(buf, bufsz, &pos, 0u)) return 0;

    /* Call header */
    if (!rpc_put_u32(buf, bufsz, &pos, xid))         return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_CALL))     return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, 2u))           return 0;  /* rpcvers */
    if (!rpc_put_u32(buf, bufsz, &pos, prog))         return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, vers))         return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, NFS_PROC_NULL)) return 0;

    /* RPCSEC_GSS credential */
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS))   return 0;  /* flavor */
    if (!rpc_put_u32(buf, bufsz, &pos, cred_body_len)) return 0; /* len */
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_VERSION)) return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, gss_proc))     return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, 0u))           return 0;  /* seq_num */
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_SVC_NONE)) return 0;
    /* handle opaque<> */
    if (!rpc_put_opaque(buf, bufsz, &pos, handle, handle_len)) return 0;

    /* AUTH_NONE verifier */
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_AUTH_NONE)) return 0;
    if (!rpc_put_u32(buf, bufsz, &pos, 0u))            return 0;

    /* Procedure body: the GSS token as opaque<> */
    if (!rpc_put_opaque(buf, bufsz, &pos,
                        (const uint8_t *)token->value,
                        (uint32_t)token->length)) return 0;

    /* Fill in record marker (body = everything after the 4-byte marker) */
    uint32_t body_len = (uint32_t)(pos - 4);
    size_t mpos = marker_pos;
    rpc_put_u32(buf, bufsz, &mpos, RPC_LAST_FRAG | body_len);

    return pos;
}

/*
 * build_gss_data_null -- build an RPCSEC_GSS DATA NULL call.
 *
 * RFC 2203 S5.3.3.3: verifier = gss_get_mic over the call header bytes
 * (xid through end of credential body, inclusive).
 *
 * Returns total byte count, or 0 on error.
 */
static size_t build_gss_data_null(uint8_t *buf, size_t bufsz,
                                   uint32_t xid, uint32_t prog, uint32_t vers,
                                   struct gss_ctx *gc,
                                   char *errbuf, size_t errsz)
{
    gc->gc_seq_num++;

    uint32_t handle_padded = (gc->gc_handle_len + 3u) & ~3u;
    uint32_t cred_body_len = 4 + 4 + 4 + 4 + 4 + handle_padded;

    size_t pos = 0;
    size_t marker_pos = pos;
    if (!rpc_put_u32(buf, bufsz, &pos, 0u)) goto overflow;

    /* Record the start of the call header (xid offset = pos now = 4) */
    size_t header_start = pos;

    if (!rpc_put_u32(buf, bufsz, &pos, xid))              goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, RPC_CALL))          goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, 2u))                goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, prog))              goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, vers))              goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, NFS_PROC_NULL))     goto overflow;

    /* Credential */
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS))        goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, cred_body_len))     goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_VERSION)) goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_DATA))   goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, gc->gc_seq_num))    goto overflow;
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_SVC_NONE)) goto overflow;
    if (!rpc_put_opaque(buf, bufsz, &pos,
                        gc->gc_handle, gc->gc_handle_len)) goto overflow;

    /* Record end of header for MIC computation */
    size_t header_end = pos;

    /* Verifier: gss_get_mic over [header_start, header_end) */
    gss_buffer_desc msg_buf;
    msg_buf.value  = buf + header_start;
    msg_buf.length = header_end - header_start;

    gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 min_stat;
    OM_uint32 maj_stat = gss_get_mic(&min_stat, gc->gc_ctx,
                                      GSS_C_QOP_DEFAULT,
                                      &msg_buf, &mic_buf);
    if (maj_stat != GSS_S_COMPLETE) {
        snprintf(errbuf, errsz, "gss_get_mic: maj=%u min=%u",
                 maj_stat, min_stat);
        return 0;
    }

    /* Write RPCSEC_GSS verifier with the MIC token as body */
    if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS))      { gss_release_buffer(&min_stat, &mic_buf); goto overflow; }
    if (!rpc_put_opaque(buf, bufsz, &pos,
                        (const uint8_t *)mic_buf.value,
                        (uint32_t)mic_buf.length))        { gss_release_buffer(&min_stat, &mic_buf); goto overflow; }
    gss_release_buffer(&min_stat, &mic_buf);

    /* No procedure body for NULL */

    /* Fill record marker */
    uint32_t body_len = (uint32_t)(pos - 4);
    size_t mpos = marker_pos;
    rpc_put_u32(buf, bufsz, &mpos, RPC_LAST_FRAG | body_len);
    return pos;

overflow:
    snprintf(errbuf, errsz, "build_gss_data_null: buffer overflow");
    return 0;
}

/* -----------------------------------------------------------------------
 * RPCSEC_GSS reply parsing
 * --------------------------------------------------------------------- */

/*
 * read_rpc_reply -- read one TCP record from fd, write body to buf.
 * Returns body_len on success, -1 on error (errbuf filled).
 */
static ssize_t read_rpc_reply(int fd, uint8_t *buf, size_t bufsz,
                               char *errbuf, size_t errsz)
{
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
        snprintf(errbuf, errsz, "multi-fragment reply not supported");
        return -1;
    }
    uint32_t body_len = marker & ~RPC_LAST_FRAG;
    if (body_len == 0 || body_len > bufsz) {
        snprintf(errbuf, errsz, "reply body_len %u out of range", body_len);
        return -1;
    }
    if (rpc_readn(fd, buf, body_len) != (ssize_t)body_len) {
        snprintf(errbuf, errsz, "read reply body: %s",
                 errno ? strerror(errno) : "EOF");
        return -1;
    }
    return (ssize_t)body_len;
}

/*
 * parse_gss_init_reply -- parse an RPCSEC_GSS INIT reply.
 *
 * Fills gc->gc_handle and returns the GSS token in *token_out.
 * token_out->value must be freed by the caller with free().
 *
 * Returns 1 if context is complete (GSS_S_COMPLETE from server),
 *         0 if more tokens needed (CONTINUE),
 *        -1 on error.
 */
static int parse_gss_init_reply(const uint8_t *body, size_t body_len,
                                 uint32_t expected_xid,
                                 struct gss_ctx *gc,
                                 gss_buffer_t token_out,
                                 char *errbuf, size_t errsz)
{
    size_t pos = 0;
    uint32_t xid, msg_type, reply_stat;
    uint32_t verf_flavor, verf_len;
    uint32_t accept_stat;

    token_out->value  = NULL;
    token_out->length = 0;

    if (!rpc_get_u32(body, body_len, &pos, &xid) ||
        !rpc_get_u32(body, body_len, &pos, &msg_type) ||
        !rpc_get_u32(body, body_len, &pos, &reply_stat)) {
        snprintf(errbuf, errsz, "INIT reply: short header");
        return -1;
    }
    if (xid != expected_xid) {
        snprintf(errbuf, errsz, "INIT reply: xid mismatch");
        return -1;
    }
    if (msg_type != RPC_REPLY || reply_stat != RPC_MSG_ACCEPTED) {
        snprintf(errbuf, errsz, "INIT reply: rejected msg=%u stat=%u",
                 msg_type, reply_stat);
        return -1;
    }

    /* Verifier: for INIT, server may include GSS token in verifier body */
    if (!rpc_get_u32(body, body_len, &pos, &verf_flavor) ||
        !rpc_get_u32(body, body_len, &pos, &verf_len)) {
        snprintf(errbuf, errsz, "INIT reply: short verifier");
        return -1;
    }
    uint32_t verf_padded = (verf_len + 3u) & ~3u;
    if (!rpc_skip(body_len, &pos, verf_padded)) {
        snprintf(errbuf, errsz, "INIT reply: verifier truncated");
        return -1;
    }

    if (!rpc_get_u32(body, body_len, &pos, &accept_stat)) {
        snprintf(errbuf, errsz, "INIT reply: no accept_stat");
        return -1;
    }
    if (accept_stat != RPC_SUCCESS) {
        snprintf(errbuf, errsz, "INIT reply: accept_stat %u", accept_stat);
        return -1;
    }

    /*
     * RPCSEC_GSS INIT resok (RFC 2203 S5.2.3.1):
     *   handle        : opaque<>
     *   gss_major     : uint32
     *   gss_minor     : uint32
     *   seq_window    : uint32
     *   token         : opaque<>
     */
    uint32_t handle_len;
    if (!rpc_get_u32(body, body_len, &pos, &handle_len)) {
        snprintf(errbuf, errsz, "INIT resok: no handle_len");
        return -1;
    }
    if (handle_len > sizeof(gc->gc_handle)) {
        snprintf(errbuf, errsz, "INIT resok: handle too long (%u)", handle_len);
        return -1;
    }
    if (pos + handle_len > body_len) {
        snprintf(errbuf, errsz, "INIT resok: handle truncated");
        return -1;
    }
    memcpy(gc->gc_handle, body + pos, handle_len);
    gc->gc_handle_len = handle_len;
    uint32_t handle_padded = (handle_len + 3u) & ~3u;
    if (!rpc_skip(body_len, &pos, handle_padded)) {
        snprintf(errbuf, errsz, "INIT resok: handle padding truncated");
        return -1;
    }

    uint32_t gss_major, gss_minor, seq_window;
    if (!rpc_get_u32(body, body_len, &pos, &gss_major) ||
        !rpc_get_u32(body, body_len, &pos, &gss_minor) ||
        !rpc_get_u32(body, body_len, &pos, &seq_window)) {
        snprintf(errbuf, errsz, "INIT resok: short gss status");
        return -1;
    }

    /* Token: opaque<> -- may be empty if context is complete */
    uint32_t token_len;
    if (!rpc_get_u32(body, body_len, &pos, &token_len)) {
        snprintf(errbuf, errsz, "INIT resok: no token_len");
        return -1;
    }
    if (token_len > 0) {
        if (pos + token_len > body_len) {
            snprintf(errbuf, errsz, "INIT resok: token truncated");
            return -1;
        }
        token_out->value = malloc(token_len);
        if (!token_out->value) {
            snprintf(errbuf, errsz, "INIT resok: malloc failed");
            return -1;
        }
        memcpy(token_out->value, body + pos, token_len);
        token_out->length = token_len;
    }

    /* gss_major == GSS_S_COMPLETE means context fully established */
    return (gss_major == GSS_S_COMPLETE) ? 1 : 0;
}

/*
 * parse_data_reply_verifier -- parse a DATA NULL reply and verify the
 * RPCSEC_GSS verifier (gss_verify_mic over the 4-byte seq_num).
 *
 * Returns 0 on success, -1 on error.
 */
static int parse_data_reply_verifier(const uint8_t *body, size_t body_len,
                                      uint32_t expected_xid,
                                      struct gss_ctx *gc,
                                      char *errbuf, size_t errsz)
{
    size_t pos = 0;
    uint32_t xid, msg_type, reply_stat;
    uint32_t verf_flavor, verf_len;
    uint32_t accept_stat = 0;

    if (!rpc_get_u32(body, body_len, &pos, &xid) ||
        !rpc_get_u32(body, body_len, &pos, &msg_type) ||
        !rpc_get_u32(body, body_len, &pos, &reply_stat)) {
        snprintf(errbuf, errsz, "DATA reply: short header");
        return -1;
    }
    if (xid != expected_xid || msg_type != RPC_REPLY ||
        reply_stat != RPC_MSG_ACCEPTED) {
        snprintf(errbuf, errsz,
                 "DATA reply: unexpected xid=%u msg=%u stat=%u",
                 xid, msg_type, reply_stat);
        return -1;
    }

    if (!rpc_get_u32(body, body_len, &pos, &verf_flavor) ||
        !rpc_get_u32(body, body_len, &pos, &verf_len)) {
        snprintf(errbuf, errsz, "DATA reply: short verifier header");
        return -1;
    }

    if (verf_flavor == RPCSEC_GSS && verf_len > 0) {
        /* Verify: server MIC is over 4-byte seq_num (big-endian) */
        if (pos + verf_len > body_len) {
            snprintf(errbuf, errsz, "DATA reply: verifier body truncated");
            return -1;
        }
        gss_buffer_desc mic_buf;
        mic_buf.value  = (void *)(body + pos);
        mic_buf.length = verf_len;

        uint8_t seq_buf[4];
        size_t sq = 0;
        rpc_put_u32(seq_buf, 4, &sq, gc->gc_seq_num);

        gss_buffer_desc msg_buf;
        msg_buf.value  = seq_buf;
        msg_buf.length = 4;

        OM_uint32 min_stat, qop_state;
        OM_uint32 maj_stat = gss_verify_mic(&min_stat, gc->gc_ctx,
                                             &msg_buf, &mic_buf, &qop_state);
        if (maj_stat != GSS_S_COMPLETE) {
            snprintf(errbuf, errsz,
                     "gss_verify_mic on reply verifier: maj=%u min=%u",
                     maj_stat, min_stat);
            return -1;
        }
    }

    uint32_t verf_padded = (verf_len + 3u) & ~3u;
    if (!rpc_skip(body_len, &pos, verf_padded)) {
        snprintf(errbuf, errsz, "DATA reply: verifier skip failed");
        return -1;
    }

    if (!rpc_get_u32(body, body_len, &pos, &accept_stat) ||
        accept_stat != RPC_SUCCESS) {
        snprintf(errbuf, errsz, "DATA reply: accept_stat %u", accept_stat);
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Option parsing
 * --------------------------------------------------------------------- */

struct options {
    const char *o_host;
    const char *o_port;
    const char *o_principal;
    long        o_iterations;
    int         o_verbose;
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --host HOST [options]\n"
            "\n"
            "Options:\n"
            "  --host HOST         NFS server hostname or IP (required)\n"
            "  --port PORT         Port number (default: 2049)\n"
            "  --principal NAME    Service principal (default: nfs@HOST)\n"
            "  --iterations N      NULL calls after context setup (default: 1)\n"
            "  --verbose           Show GSS exchange details\n"
            "\n"
            "Tests RPCSEC_GSS (RFC 2203) Kerberos 5 context establishment and\n"
            "authenticated NULL RPC calls against an NFS server.\n",
            prog);
    exit(EXIT_FAILURE);
}

static void parse_options(int argc, char **argv, struct options *o)
{
    static const struct option long_opts[] = {
        { "host",       required_argument, NULL, 'H' },
        { "port",       required_argument, NULL, 'p' },
        { "principal",  required_argument, NULL, 'P' },
        { "iterations", required_argument, NULL, 'i' },
        { "verbose",    no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 }
    };

    memset(o, 0, sizeof(*o));
    o->o_port       = "2049";
    o->o_iterations = 1;

    int ch;
    while ((ch = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'H': o->o_host       = optarg;       break;
        case 'p': o->o_port       = optarg;       break;
        case 'P': o->o_principal  = optarg;       break;
        case 'i': o->o_iterations = atol(optarg); break;
        case 'v': o->o_verbose    = 1;            break;
        default:  usage(argv[0]);
        }
    }
    if (!o->o_host) {
        fprintf(stderr, "Error: --host is required\n\n");
        usage(argv[0]);
    }
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    struct options opts;
    parse_options(argc, argv, &opts);

    /* Build default principal "nfs@HOST" if not specified */
    char default_principal[512];
    if (!opts.o_principal) {
        snprintf(default_principal, sizeof(default_principal),
                 "nfs@%s", opts.o_host);
        opts.o_principal = default_principal;
    }

    printf("nfs_krb5_test: %s:%s principal=%s\n",
           opts.o_host, opts.o_port, opts.o_principal);

    /* --- Connect --- */
    char errbuf[512];
    int fd = tcp_connect_host(opts.o_host, opts.o_port, errbuf, sizeof(errbuf));
    if (fd < 0) {
        fprintf(stderr, "connect: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    /* --- GSS context establishment --- */
    struct gss_ctx gc;
    memset(&gc, 0, sizeof(gc));
    gc.gc_ctx = GSS_C_NO_CONTEXT;

    /* Import the service name */
    gss_buffer_desc name_buf;
    name_buf.value  = (void *)opts.o_principal;
    name_buf.length = strlen(opts.o_principal);

    OM_uint32 min_stat, maj_stat;
    maj_stat = gss_import_name(&min_stat, &name_buf,
                                GSS_C_NT_HOSTBASED_SERVICE,
                                &gc.gc_svc_name);
    if (maj_stat != GSS_S_COMPLETE) {
        fprintf(stderr, "gss_import_name('%s'): maj=%u min=%u\n",
                opts.o_principal, maj_stat, min_stat);
        close(fd);
        return EXIT_FAILURE;
    }
    if (opts.o_verbose)
        printf("  gss_import_name OK\n");

    /* Context establishment loop */
    gss_buffer_desc in_token  = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    int complete = 0;
    uint32_t xid = (uint32_t)getpid();
    uint32_t gss_proc = RPCSEC_GSS_INIT;

    uint8_t  call_buf[RPC_MSG_MAX];
    uint8_t  reply_buf[RPC_MSG_MAX];

    while (!complete) {
        maj_stat = gss_init_sec_context(
            &min_stat,
            GSS_C_NO_CREDENTIAL,
            &gc.gc_ctx,
            gc.gc_svc_name,
            GSS_C_NO_OID,
            GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG,
            0,
            GSS_C_NO_CHANNEL_BINDINGS,
            &in_token,
            &gc.gc_mech,
            &out_token,
            NULL,
            NULL);

        /* Free the input token from the previous round */
        if (in_token.value) {
            free(in_token.value);
            in_token.value  = NULL;
            in_token.length = 0;
        }

        if (maj_stat != GSS_S_COMPLETE &&
            maj_stat != GSS_S_CONTINUE_NEEDED) {
            fprintf(stderr, "gss_init_sec_context: maj=%u min=%u\n",
                    maj_stat, min_stat);
            gss_release_buffer(&min_stat, &out_token);
            gss_release_name(&min_stat, &gc.gc_svc_name);
            close(fd);
            return EXIT_FAILURE;
        }

        if (opts.o_verbose)
            printf("  gss_init_sec_context: out_token=%zu bytes gss_proc=%u\n",
                   out_token.length, gss_proc);

        if (out_token.length > 0) {
            /* Send INIT or CONTINUE_INIT */
            xid++;
            size_t call_len = build_gss_init_call(
                call_buf, sizeof(call_buf), xid,
                NFS_PROGRAM, NFS_VERSION_4, gss_proc,
                gc.gc_handle, gc.gc_handle_len, &out_token);
            gss_release_buffer(&min_stat, &out_token);

            if (call_len == 0) {
                fprintf(stderr, "build_gss_init_call: buffer overflow\n");
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return EXIT_FAILURE;
            }
            if (rpc_writen(fd, call_buf, call_len) != (ssize_t)call_len) {
                fprintf(stderr, "write INIT call: %s\n", strerror(errno));
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return EXIT_FAILURE;
            }

            /* Read INIT reply */
            ssize_t rlen = read_rpc_reply(fd, reply_buf, sizeof(reply_buf),
                                           errbuf, sizeof(errbuf));
            if (rlen < 0) {
                fprintf(stderr, "read INIT reply: %s\n", errbuf);
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return EXIT_FAILURE;
            }

            int done = parse_gss_init_reply(reply_buf, (size_t)rlen, xid,
                                             &gc, &in_token, errbuf,
                                             sizeof(errbuf));
            if (done < 0) {
                fprintf(stderr, "parse INIT reply: %s\n", errbuf);
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return EXIT_FAILURE;
            }
            if (opts.o_verbose)
                printf("  INIT reply: handle_len=%u done=%d\n",
                       gc.gc_handle_len, done);
        } else {
            gss_release_buffer(&min_stat, &out_token);
        }

        if (maj_stat == GSS_S_COMPLETE)
            complete = 1;
        else
            gss_proc = RPCSEC_GSS_CONTINUE;
    }

    printf("  RPCSEC_GSS context established (handle_len=%u)\n",
           gc.gc_handle_len);

    /* --- DATA NULL calls --- */
    int result = EXIT_SUCCESS;
    for (long i = 0; i < opts.o_iterations; i++) {
        xid++;
        size_t call_len = build_gss_data_null(call_buf, sizeof(call_buf),
                                               xid, NFS_PROGRAM, NFS_VERSION_4,
                                               &gc, errbuf, sizeof(errbuf));
        if (call_len == 0) {
            fprintf(stderr, "build_gss_data_null: %s\n", errbuf);
            result = EXIT_FAILURE;
            break;
        }
        if (rpc_writen(fd, call_buf, call_len) != (ssize_t)call_len) {
            fprintf(stderr, "write DATA NULL: %s\n", strerror(errno));
            result = EXIT_FAILURE;
            break;
        }

        ssize_t rlen = read_rpc_reply(fd, reply_buf, sizeof(reply_buf),
                                       errbuf, sizeof(errbuf));
        if (rlen < 0) {
            fprintf(stderr, "read DATA reply: %s\n", errbuf);
            result = EXIT_FAILURE;
            break;
        }
        if (parse_data_reply_verifier(reply_buf, (size_t)rlen, xid,
                                       &gc, errbuf, sizeof(errbuf)) < 0) {
            fprintf(stderr, "verify DATA reply: %s\n", errbuf);
            result = EXIT_FAILURE;
            break;
        }
        if (opts.o_verbose)
            printf("  DATA NULL [%ld]: OK (seq=%u)\n", i + 1, gc.gc_seq_num);
        else
            printf("  NULL call %ld/%ld OK\n", i + 1, opts.o_iterations);
    }

    /* --- Cleanup --- */
    gss_buffer_desc out_tok2 = GSS_C_EMPTY_BUFFER;
    gss_delete_sec_context(&min_stat, &gc.gc_ctx, &out_tok2);
    gss_release_buffer(&min_stat, &out_tok2);
    gss_release_name(&min_stat, &gc.gc_svc_name);
    if (in_token.value)
        free(in_token.value);
    close(fd);

    if (result == EXIT_SUCCESS)
        printf("PASS\n");
    else
        printf("FAIL\n");

    return result;
}
