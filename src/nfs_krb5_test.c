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
#include "gss_wire.h"
#include "nfs_error.h"
#include "krb5_error.h"
#include "diagnose.h"

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

/* -----------------------------------------------------------------------
 * GSS status classification
 * --------------------------------------------------------------------- */

/*
 * krb5_classify_gss -- map a GSS-API (major, minor) status pair into a
 * canonical krb5_error_code from the taxonomy in krb5_error.h.
 *
 * The major status carries a routine error from the GSS-API spec; we
 * switch on it first because those values are vendor-portable.
 *
 * For the krb5 mech-specific minor status (which is what carries
 * "Clock skew", "Ticket expired", "Server not in database", etc.) the
 * raw integer values are MIT-internal and not portable to Heimdal.
 * Rather than #ifdef on the krb5 implementation, we ask GSS for the
 * mech-specific display string via gss_display_status() and pattern
 * match on substrings.  The downside is locale fragility; the upside
 * is that it works on any conformant GSS implementation.
 *
 * Patterns include both MIT and Heimdal phrasings where they differ.
 * MIT phrasing is listed first; Heimdal alternative follows.  Neither
 * list is exhaustive -- if a new phrasing is needed, add it here.
 *
 * Returns the most specific krb5_error_code we can identify, falling
 * back to KRB5_ERR_GSS_INIT_FAILED if nothing matches.
 */
static enum krb5_error_code
krb5_classify_gss(OM_uint32 maj, OM_uint32 min, gss_OID mech)
{
    /* GSS major routine errors -- vendor portable */
    OM_uint32 routine = GSS_ROUTINE_ERROR(maj);
    if (routine == GSS_S_BAD_NAME)             return KRB5_ERR_GSS_BAD_NAME;
    if (routine == GSS_S_BAD_NAMETYPE)         return KRB5_ERR_GSS_BAD_NAME;
    if (routine == GSS_S_BAD_MECH)             return KRB5_ERR_GSS_BAD_MECH;
    if (routine == GSS_S_NO_CRED)              return KRB5_ERR_GSS_NO_CRED;
    if (routine == GSS_S_DEFECTIVE_TOKEN)      return KRB5_ERR_GSS_DEFECTIVE_TOKEN;
    if (routine == GSS_S_DEFECTIVE_CREDENTIAL) return KRB5_ERR_GSS_DEFECTIVE_CRED;
    if (routine == GSS_S_CREDENTIALS_EXPIRED)  return KRB5_ERR_GSS_CRED_EXPIRED;
    if (routine == GSS_S_CONTEXT_EXPIRED)      return KRB5_ERR_GSS_CONTEXT_EXPIRED;
    /* GSS_S_BAD_MIC and GSS_S_BAD_SIG are the same value per RFC 2744
     * errata; some headers only define BAD_SIG.  Map both to the
     * MIC-flavor symbol since that's the more commonly recognised
     * spelling in modern docs. */
#ifdef GSS_S_BAD_MIC
    if (routine == GSS_S_BAD_MIC)              return KRB5_ERR_GSS_BAD_MIC;
#endif
    if (routine == GSS_S_BAD_SIG)              return KRB5_ERR_GSS_BAD_MIC;

    /*
     * Mech-specific minor: walk the GSS message context until we get
     * a string we can recognise, or until display_status reports
     * GSS_S_COMPLETE with no further messages.
     */
    OM_uint32           ms;
    OM_uint32           message_context = 0;
    enum krb5_error_code matched = KRB5_ERR_GSS_INIT_FAILED;

    do {
        gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
        OM_uint32 dms = gss_display_status(&ms, min, GSS_C_MECH_CODE,
                                           mech, &message_context, &msg);
        if (GSS_ERROR(dms))
            break;

        const char *s = (const char *)msg.value;
        if (s) {
            /*
             * Order matters: more specific patterns first so the
             * generic INTEGRITY catch doesn't shadow KVNO.
             */
            if (strstr(s, "lock skew") ||
                /* Heimdal: "time skew too great" */
                strstr(s, "time skew")) {
                matched = KRB5_ERR_CLOCK_SKEW;
            } else if (strstr(s, "Cannot find KDC") ||
                       strstr(s, "Cannot contact any KDC") ||
                       strstr(s, "Connection refused") ||
                       /* Heimdal: "unable to reach any KDC" */
                       strstr(s, "unable to reach any KDC")) {
                matched = KRB5_ERR_KDC_UNREACHABLE;
            } else if (strstr(s, "No credentials cache") ||
                       strstr(s, "credentials cache file") ||
                       strstr(s, "No such file or directory") ||
                       /* Heimdal: "no ticket file" / "no credentials" */
                       strstr(s, "no ticket file") ||
                       strstr(s, "no credentials")) {
                matched = KRB5_ERR_NO_TGT;
            } else if (strstr(s, "icket expired") ||
                       /* Heimdal: "ticket is expired" */
                       strstr(s, "ticket is expired")) {
                matched = KRB5_ERR_TGT_EXPIRED;
            } else if (strstr(s, "ot yet valid") ||
                       /* Heimdal: "ticket not yet valid" */
                       strstr(s, "ticket not yet valid")) {
                matched = KRB5_ERR_TGT_NOT_YET_VALID;
            } else if (strstr(s, "key table entry not found") ||
                       strstr(s, "Key table entry not found") ||
                       strstr(s, "no suitable keys") ||
                       /* Heimdal: "no entry for" (keytab) */
                       strstr(s, "no entry for")) {
                matched = KRB5_ERR_KEYTAB_NO_PRINCIPAL;
            } else if (strstr(s, "ey version") &&
                       (strstr(s, "not available") ||
                        strstr(s, "wrong"))) {
                matched = KRB5_ERR_BAD_KVNO;
            } else if (strstr(s, "Decrypt integrity check") ||
                       strstr(s, "decrypt integrity") ||
                       strstr(s, "BAD_INTEGRITY") ||
                       /* Heimdal: "failed to decrypt" */
                       strstr(s, "failed to decrypt")) {
                matched = KRB5_ERR_BAD_INTEGRITY;
            } else if ((strstr(s, "Server") && strstr(s, "not found in")) ||
                       /* Heimdal: "Server not found in Kerberos database" */
                       (strstr(s, "not found in Kerberos"))) {
                matched = KRB5_ERR_PRINCIPAL_UNKNOWN;
            } else if (strstr(s, "ncryption type") &&
                       strstr(s, "supported")) {
                matched = KRB5_ERR_BAD_ENCTYPE;
            } else if ((strstr(s, "Permission denied") &&
                        strstr(s, "keytab")) ||
                       /* Heimdal: "error opening keytab" */
                       strstr(s, "error opening keytab")) {
                matched = KRB5_ERR_KEYTAB_NOT_READABLE;
            } else if (strstr(s, "Pre-authentication failed") ||
                       strstr(s, "PREAUTH_FAILED") ||
                       /* Heimdal: "preauthentication failed" */
                       strstr(s, "preauthentication failed")) {
                matched = KRB5_ERR_PREAUTH_FAILED;
            } else if (strstr(s, "not in the same realm") ||
                       strstr(s, "BAD_REALM") ||
                       /* Heimdal: "wrong realm" */
                       strstr(s, "wrong realm")) {
                matched = KRB5_ERR_BAD_REALM;
            }
        }
        gss_release_buffer(&ms, &msg);

        if (matched != KRB5_ERR_GSS_INIT_FAILED)
            break;
    } while (message_context != 0);

    return matched;
}

/*
 * krb5_emit_gss_failure -- pretty-print a GSS failure via the canonical
 * taxonomy and return the symbolic code's numeric value (for use as
 * the program exit status).
 *
 * Builds a context line from the operation name and the raw GSS
 * major/minor pair so the user can still recognise the failure if
 * the classifier picked the wrong category.
 */
static int krb5_emit_gss_failure(const char *operation,
                                 OM_uint32 maj, OM_uint32 min, gss_OID mech)
{
    enum krb5_error_code code = krb5_classify_gss(maj, min, mech);
    char ctx[128];
    snprintf(ctx, sizeof(ctx),
             "%s: maj=0x%08x min=0x%08x", operation, maj, min);
    nfs_error_emit_one(stderr, (int)code, ctx);
    return (int)code;
}

/* -----------------------------------------------------------------------
 * Option definitions (forward here so probe_secinfo() can use them)
 * --------------------------------------------------------------------- */

struct options {
    const char *o_host;
    const char *o_port;
    const char *o_principal;
    long        o_iterations;
    int         o_verbose;
    int         o_diagnose;          /* run pre-flight checks and exit */
    int         o_print_error_table; /* dump krb5 error taxonomy and exit */
    int         o_stress;            /* run all iterations, count per code */
    int         o_probe_secinfo;     /* run SECINFO probe and exit */
    const char *o_krb5_trace;        /* path for KRB5_TRACE; NULL = off */
    uint32_t    o_sec;               /* RPCSEC_GSS_SVC_NONE/INTEG/PRIV */
};

/* -----------------------------------------------------------------------
 * NFSv4 COMPOUND / SECINFO probe
 *
 * Implements a two-step security probe:
 *   1. COMPOUND(AUTH_SYS, minorversion=0): PUTROOTFH
 *      -> NFS4_OK   : server accepts AUTH_SYS at the root
 *      -> WRONGSEC  : server requires a different flavor
 *   2. COMPOUND(AUTH_SYS, minorversion=1): PUTROOTFH + SECINFO_NO_NAME
 *      -> parse secinfo4<> list to find what flavors are offered
 *      -> check if the requested --sec flavor is present
 *
 * SECINFO / SECINFO_NO_NAME are special: the server MUST NOT return
 * NFS4ERR_WRONGSEC for them (RFC 8881 S18.30.5 / RFC 5661 S18.45.5).
 * We can therefore send the SECINFO probe with plain AUTH_SYS even when
 * the server requires Kerberos for all other operations.
 *
 * NFSv4 wire constants used here:
 * --------------------------------------------------------------------- */

/* NFSv4 procedure number inside the RPC program */
#define NFS4_PROC_COMPOUND      1u

/* NFSv4 operation codes (RFC 8881 Table 5) */
#define OP_PUTROOTFH            24u
#define OP_SECINFO              33u
#define OP_SECINFO_NO_NAME      51u   /* NFSv4.1+ (RFC 5661 S18.45) */

/* secinfo_style4 values (RFC 5661 S18.45) */
#define SECINFO_STYLE4_CURRENT_FH   0u
#define SECINFO_STYLE4_PARENT       1u

/* NFS4 status codes (RFC 8881 Table 6) */
#define NFS4_OK                 0u
#define NFS4ERR_WRONGSEC        10009u
#define NFS4ERR_OP_NOT_IN_SESSION 10044u

/*
 * build_authsys_compound -- build a bare NFSv4 COMPOUND with an AUTH_SYS
 * credential over TCP.  The credential uses uid=65534, gid=65534 (nobody)
 * so the probe never accidentally gains real server access.
 *
 * The COMPOUND args are supplied by the caller in cmpd_body/cmpd_len.
 * Returns total byte count including the TCP record marker, or 0 on
 * buffer overflow.
 */
static size_t build_authsys_compound(uint8_t *buf, size_t bufsz,
                                      uint32_t xid,
                                      const uint8_t *cmpd_body,
                                      size_t cmpd_len)
{
	/*
	 * AUTH_SYS body (RFC 5531 S8.1):
	 *   stamp(4) + machinename_len(4) [+pad] + uid(4) + gid(4) + gids_len(4)
	 * Empty machinename ("") is 4 bytes of length=0 with no data/padding.
	 */
	const uint32_t authsys_len = 20u;   /* 5 * 4 bytes */
	size_t pos = 0;

	/* TCP record marker -- filled in at the end */
	size_t marker_pos = pos;
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))         return 0;

	/* RPC call header */
	if (!rpc_put_u32(buf, bufsz, &pos, xid))         return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, RPC_CALL))    return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, 2u))          return 0; /* rpcvers */
	if (!rpc_put_u32(buf, bufsz, &pos, NFS_PROGRAM)) return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, NFS_VERSION_4)) return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, NFS4_PROC_COMPOUND)) return 0;

	/* AUTH_SYS credential */
	if (!rpc_put_u32(buf, bufsz, &pos, RPC_AUTH_SYS))  return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, authsys_len))    return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, 0x12345678u))    return 0; /* stamp */
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))             return 0; /* machinename="" */
	if (!rpc_put_u32(buf, bufsz, &pos, 65534u))         return 0; /* uid=nobody */
	if (!rpc_put_u32(buf, bufsz, &pos, 65534u))         return 0; /* gid=nogroup */
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))             return 0; /* gids count */

	/* AUTH_NONE verifier */
	if (!rpc_put_u32(buf, bufsz, &pos, RPC_AUTH_NONE)) return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))            return 0;

	/* COMPOUND args body */
	if (pos + cmpd_len > bufsz)
		return 0;
	memcpy(buf + pos, cmpd_body, cmpd_len);
	pos += cmpd_len;

	/* Fill in record marker */
	uint32_t body_bytes = (uint32_t)(pos - 4);
	size_t mpos = marker_pos;
	rpc_put_u32(buf, bufsz, &mpos, RPC_LAST_FRAG | body_bytes);

	return pos;
}

/*
 * parse_nfs4_compound_hdr -- parse a COMPOUND4res reply header.
 *
 * On return, *pos is positioned at the first op result in resarray.
 * *nops is the resarray count.  Returns 0 on success, -1 on error.
 */
static int parse_nfs4_compound_hdr(const uint8_t *body, size_t body_len,
                                    uint32_t expected_xid,
                                    uint32_t *compound_status,
                                    size_t *pos, uint32_t *nops,
                                    char *errbuf, size_t errsz)
{
	uint32_t xid, msg_type, reply_stat;
	uint32_t verf_flavor, verf_len;
	uint32_t accept_stat;
	uint32_t tag_len;

	*pos = 0;

	if (!rpc_get_u32(body, body_len, pos, &xid) ||
	    !rpc_get_u32(body, body_len, pos, &msg_type) ||
	    !rpc_get_u32(body, body_len, pos, &reply_stat)) {
		snprintf(errbuf, errsz, "COMPOUND reply: short header");
		return -1;
	}
	if (xid != expected_xid) {
		snprintf(errbuf, errsz, "COMPOUND reply: xid mismatch "
		         "(got %u want %u)", xid, expected_xid);
		return -1;
	}
	if (msg_type != RPC_REPLY || reply_stat != RPC_MSG_ACCEPTED) {
		snprintf(errbuf, errsz, "COMPOUND reply: msg rejected "
		         "msg_type=%u reply_stat=%u", msg_type, reply_stat);
		return -1;
	}

	/* verifier */
	if (!rpc_get_u32(body, body_len, pos, &verf_flavor) ||
	    !rpc_get_u32(body, body_len, pos, &verf_len)) {
		snprintf(errbuf, errsz, "COMPOUND reply: short verifier");
		return -1;
	}
	uint32_t verf_padded = (verf_len + 3u) & ~3u;
	if (!rpc_skip(body_len, pos, verf_padded)) {
		snprintf(errbuf, errsz, "COMPOUND reply: verifier body truncated");
		return -1;
	}

	if (!rpc_get_u32(body, body_len, pos, &accept_stat)) {
		snprintf(errbuf, errsz, "COMPOUND reply: no accept_stat");
		return -1;
	}
	if (accept_stat != RPC_SUCCESS) {
		snprintf(errbuf, errsz, "COMPOUND reply: accept_stat=%u", accept_stat);
		return -1;
	}

	/* COMPOUND4res: status + tag + resarray */
	if (!rpc_get_u32(body, body_len, pos, compound_status)) {
		snprintf(errbuf, errsz, "COMPOUND4res: no status");
		return -1;
	}
	if (!rpc_get_u32(body, body_len, pos, &tag_len)) {
		snprintf(errbuf, errsz, "COMPOUND4res: no tag_len");
		return -1;
	}
	uint32_t tag_padded = (tag_len + 3u) & ~3u;
	if (!rpc_skip(body_len, pos, tag_padded)) {
		snprintf(errbuf, errsz, "COMPOUND4res: tag truncated");
		return -1;
	}
	if (!rpc_get_u32(body, body_len, pos, nops)) {
		snprintf(errbuf, errsz, "COMPOUND4res: no resarray count");
		return -1;
	}
	return 0;
}

/*
 * gss_service_name -- map secinfo service value to a human-readable label.
 */
static const char *gss_service_name(uint32_t service)
{
	if (service == RPCSEC_GSS_SVC_NONE)  return "krb5";
	if (service == RPCSEC_GSS_SVC_INTEG) return "krb5i";
	if (service == RPCSEC_GSS_SVC_PRIV)  return "krb5p";
	return "unknown";
}

/*
 * parse_and_print_secinfo -- consume and print a secinfo4<> array from the
 * body at *pos.  The array describes what security flavors the server
 * accepts for the current file handle.
 *
 * Also checks whether the caller's requested service (want_svc =
 * RPCSEC_GSS_SVC_*) appears in the list and returns:
 *   0  : flavor found
 *   1  : secinfo array is empty
 *   2  : secinfo non-empty but our flavor is absent (WRONGSEC condition)
 *  -1  : parse error
 */
static int parse_and_print_secinfo(const uint8_t *body, size_t body_len,
                                    size_t *pos, uint32_t want_svc,
                                    char *errbuf, size_t errsz)
{
	uint32_t count;
	if (!rpc_get_u32(body, body_len, pos, &count)) {
		snprintf(errbuf, errsz, "secinfo4: no count");
		return -1;
	}
	if (count == 0) {
		printf("    (empty secinfo list)\n");
		return 1;
	}

	int found = 0;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t flavor;
		if (!rpc_get_u32(body, body_len, pos, &flavor)) {
			snprintf(errbuf, errsz,
			         "secinfo4[%u]: no flavor", i);
			return -1;
		}

		if (flavor == RPCSEC_GSS) {
			/* rpcsec_gss_info: oid<> + qop + service */
			uint32_t oid_len;
			if (!rpc_get_u32(body, body_len, pos, &oid_len)) {
				snprintf(errbuf, errsz,
				         "secinfo4[%u]: RPCSEC_GSS no oid_len", i);
				return -1;
			}
			uint32_t oid_padded = (oid_len + 3u) & ~3u;
			if (!rpc_skip(body_len, pos, oid_padded)) {
				snprintf(errbuf, errsz,
				         "secinfo4[%u]: RPCSEC_GSS oid truncated", i);
				return -1;
			}
			uint32_t qop, service;
			if (!rpc_get_u32(body, body_len, pos, &qop) ||
			    !rpc_get_u32(body, body_len, pos, &service)) {
				snprintf(errbuf, errsz,
				         "secinfo4[%u]: RPCSEC_GSS short qop/service",
				         i);
				return -1;
			}
			printf("    [%u] RPCSEC_GSS (Kerberos5 oid_len=%u qop=%u"
			       " service=%s)\n",
			       i, oid_len, qop, gss_service_name(service));
			if (service == want_svc)
				found = 1;
		} else if (flavor == RPC_AUTH_SYS) {
			printf("    [%u] AUTH_SYS\n", i);
		} else if (flavor == RPC_AUTH_NONE) {
			printf("    [%u] AUTH_NONE\n", i);
		} else {
			printf("    [%u] flavor=%u (unknown)\n", i, flavor);
		}
	}

	return found ? 0 : 2;
}

/*
 * probe_secinfo -- run the two-step SECINFO probe against opts->o_host.
 *
 * Step 1: Send COMPOUND(AUTH_SYS, minorversion=0): PUTROOTFH
 *         Report whether AUTH_SYS is accepted.
 *
 * Step 2: Send COMPOUND(AUTH_SYS, minorversion=1): PUTROOTFH + SECINFO_NO_NAME
 *         Parse and print the secinfo4<> list.
 *         Emit KRB5_ERR_WRONGSEC if our --sec flavor is not offered.
 *         Emit KRB5_ERR_SECINFO_EMPTY if the server returns an empty list.
 *
 * Returns NFS_ERR_OK, KRB5_ERR_WRONGSEC, or KRB5_ERR_SECINFO_EMPTY.
 */
static int probe_secinfo(const struct options *opts)
{
	char errbuf[512];
	uint8_t call_buf[RPC_MSG_MAX];
	uint8_t reply_buf[RPC_MSG_MAX];
	uint32_t xid = (uint32_t)getpid() + 0x500u;

	printf("probe-secinfo: %s:%s\n", opts->o_host, opts->o_port);

	int probe_fd = tcp_connect_host(opts->o_host, opts->o_port,
	                                errbuf, sizeof(errbuf));
	if (probe_fd < 0) {
		fprintf(stderr, "probe-secinfo: connect: %s\n", errbuf);
		return NFS_ERR_INTERNAL;
	}

	/* ------------------------------------------------------------------
	 * Step 1: AUTH_SYS COMPOUND(minorversion=0): PUTROOTFH
	 * ------------------------------------------------------------------ */

	/* Build COMPOUND args: tag="" + minorversion=0 + 1 op (PUTROOTFH) */
	uint8_t cmpd1[16];
	size_t cp = 0;
	rpc_put_u32(cmpd1, sizeof(cmpd1), &cp, 0u);   /* tag_len=0 */
	rpc_put_u32(cmpd1, sizeof(cmpd1), &cp, 0u);   /* minorversion=0 */
	rpc_put_u32(cmpd1, sizeof(cmpd1), &cp, 1u);   /* argarray count=1 */
	rpc_put_u32(cmpd1, sizeof(cmpd1), &cp, OP_PUTROOTFH); /* op, no args */

	xid++;
	size_t call_len = build_authsys_compound(call_buf, sizeof(call_buf),
	                                          xid, cmpd1, cp);
	if (call_len == 0) {
		fprintf(stderr, "probe-secinfo: call buffer overflow\n");
		close(probe_fd);
		return NFS_ERR_INTERNAL;
	}

	if (rpc_writen(probe_fd, call_buf, call_len) != (ssize_t)call_len) {
		fprintf(stderr, "probe-secinfo: write step1: %s\n",
		        strerror(errno));
		close(probe_fd);
		return NFS_ERR_INTERNAL;
	}

	ssize_t rlen = read_rpc_reply(probe_fd, reply_buf, sizeof(reply_buf),
	                               errbuf, sizeof(errbuf));
	if (rlen < 0) {
		fprintf(stderr, "probe-secinfo: read step1: %s\n", errbuf);
		close(probe_fd);
		return NFS_ERR_INTERNAL;
	}

	{
		uint32_t cmpd_status;
		size_t rpos;
		uint32_t nops;
		if (parse_nfs4_compound_hdr(reply_buf, (size_t)rlen, xid,
		                             &cmpd_status, &rpos, &nops,
		                             errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "probe-secinfo: step1 parse: %s\n",
			        errbuf);
			close(probe_fd);
			return NFS_ERR_INTERNAL;
		}

		if (cmpd_status == NFS4_OK) {
			printf("  AUTH_SYS probe: NFS4_OK "
			       "(server accepts AUTH_SYS at root)\n");
		} else if (cmpd_status == NFS4ERR_WRONGSEC) {
			printf("  AUTH_SYS probe: NFS4ERR_WRONGSEC "
			       "(server requires a different flavor)\n");
		} else {
			printf("  AUTH_SYS probe: status=%u\n", cmpd_status);
		}
	}

	/* ------------------------------------------------------------------
	 * Step 2: AUTH_SYS COMPOUND(minorversion=1): PUTROOTFH + SECINFO_NO_NAME
	 *
	 * Per RFC 5661 S18.45.5: SECINFO_NO_NAME MUST NOT return
	 * NFS4ERR_WRONGSEC, so AUTH_SYS is accepted even when Kerberos is
	 * required for all other operations.
	 * ------------------------------------------------------------------ */

	/* Build COMPOUND args: tag="" + minorversion=1 + 2 ops */
	uint8_t cmpd2[28];
	size_t cp2 = 0;
	rpc_put_u32(cmpd2, sizeof(cmpd2), &cp2, 0u);   /* tag_len=0 */
	rpc_put_u32(cmpd2, sizeof(cmpd2), &cp2, 1u);   /* minorversion=1 */
	rpc_put_u32(cmpd2, sizeof(cmpd2), &cp2, 2u);   /* argarray count=2 */
	rpc_put_u32(cmpd2, sizeof(cmpd2), &cp2, OP_PUTROOTFH);
	rpc_put_u32(cmpd2, sizeof(cmpd2), &cp2, OP_SECINFO_NO_NAME);
	rpc_put_u32(cmpd2, sizeof(cmpd2), &cp2, SECINFO_STYLE4_CURRENT_FH);

	xid++;
	call_len = build_authsys_compound(call_buf, sizeof(call_buf),
	                                   xid, cmpd2, cp2);
	if (call_len == 0) {
		fprintf(stderr, "probe-secinfo: call2 buffer overflow\n");
		close(probe_fd);
		return NFS_ERR_INTERNAL;
	}

	if (rpc_writen(probe_fd, call_buf, call_len) != (ssize_t)call_len) {
		fprintf(stderr, "probe-secinfo: write step2: %s\n",
		        strerror(errno));
		close(probe_fd);
		return NFS_ERR_INTERNAL;
	}

	rlen = read_rpc_reply(probe_fd, reply_buf, sizeof(reply_buf),
	                       errbuf, sizeof(errbuf));
	if (rlen < 0) {
		fprintf(stderr, "probe-secinfo: read step2: %s\n", errbuf);
		close(probe_fd);
		return NFS_ERR_INTERNAL;
	}

	close(probe_fd);

	uint32_t cmpd_status;
	size_t rpos;
	uint32_t nops;
	if (parse_nfs4_compound_hdr(reply_buf, (size_t)rlen, xid,
	                             &cmpd_status, &rpos, &nops,
	                             errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "probe-secinfo: step2 parse: %s\n", errbuf);
		return NFS_ERR_INTERNAL;
	}

	if (cmpd_status != NFS4_OK && cmpd_status != NFS4ERR_WRONGSEC) {
		/*
		 * Server may return OP_NOT_IN_SESSION (10044) if it strictly
		 * requires a SEQUENCE before PUTROOTFH in NFSv4.1.  Report
		 * the raw code so the user knows why SECINFO failed.
		 */
		printf("  SECINFO_NO_NAME: COMPOUND status=%u "
		       "(server may require NFSv4.1 session)\n",
		       cmpd_status);
		return NFS_ERR_INTERNAL;
	}

	/*
	 * Walk the resarray to find the SECINFO_NO_NAME result.
	 * Each element: opcode(4) + status(4) [+ op-specific result if OK]
	 */
	printf("  SECINFO_NO_NAME reply:\n");

	int sec_result = 1; /* assume empty until proven otherwise */
	for (uint32_t i = 0; i < nops; i++) {
		uint32_t op_code, op_status;
		if (!rpc_get_u32(reply_buf, (size_t)rlen, &rpos, &op_code) ||
		    !rpc_get_u32(reply_buf, (size_t)rlen, &rpos, &op_status)) {
			fprintf(stderr, "probe-secinfo: resarray[%u] truncated\n",
			        i);
			return NFS_ERR_INTERNAL;
		}
		if (op_code == OP_PUTROOTFH) {
			if (op_status != NFS4_OK) {
				printf("  PUTROOTFH: failed status=%u\n",
				       op_status);
				return NFS_ERR_INTERNAL;
			}
			/* no result body for PUTROOTFH */
		} else if (op_code == OP_SECINFO_NO_NAME) {
			if (op_status != NFS4_OK) {
				printf("  SECINFO_NO_NAME: op_status=%u\n",
				       op_status);
				return NFS_ERR_INTERNAL;
			}
			sec_result = parse_and_print_secinfo(
			    reply_buf, (size_t)rlen, &rpos,
			    opts->o_sec, errbuf, sizeof(errbuf));
			if (sec_result < 0) {
				fprintf(stderr, "probe-secinfo: secinfo parse: %s\n",
				        errbuf);
				return NFS_ERR_INTERNAL;
			}
		} else {
			/* unexpected op in reply -- skip and continue */
			if (op_status != NFS4_OK)
				break;
		}
	}

	const char *want_label = (opts->o_sec == RPCSEC_GSS_SVC_NONE)  ? "krb5"
	                        : (opts->o_sec == RPCSEC_GSS_SVC_INTEG) ? "krb5i"
	                                                                 : "krb5p";
	if (sec_result == 0) {
		printf("  Requested --sec %s: FOUND in SECINFO list\n",
		       want_label);
		return NFS_ERR_OK;
	} else if (sec_result == 1) {
		printf("  Requested --sec %s: secinfo list empty\n", want_label);
		nfs_error_emit_one(stderr, KRB5_ERR_SECINFO_EMPTY,
		                   "server returned empty SECINFO list");
		return KRB5_ERR_SECINFO_EMPTY;
	} else {
		printf("  Requested --sec %s: NOT FOUND in SECINFO list\n",
		       want_label);
		char ctx[128];
		snprintf(ctx, sizeof(ctx),
		         "%s not in server's SECINFO list for root", want_label);
		nfs_error_emit_one(stderr, KRB5_ERR_WRONGSEC, ctx);
		return KRB5_ERR_WRONGSEC;
	}
}

/* -----------------------------------------------------------------------
 * Option parsing
 * --------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --host HOST [options]\n"
            "       %s --diagnose\n"
            "       %s --print-error-table\n"
            "\n"
            "Options:\n"
            "  --host HOST           NFS server hostname or IP\n"
            "  --port PORT           Port number (default: 2049)\n"
            "  --principal NAME      Service principal (default: nfs@HOST)\n"
            "  --iterations N        NULL calls after context setup (default: 1)\n"
            "  --sec FLAVOR          RPCSEC_GSS service flavor (default: krb5)\n"
            "                        krb5  -- auth only (SVC_NONE)\n"
            "                        krb5i -- integrity (SVC_INTEG, MIC over args)\n"
            "                        krb5p -- privacy   (SVC_PRIV, gss_wrap of args)\n"
            "  --probe-secinfo       Connect to --host and run a two-step SECINFO\n"
            "                        probe (AUTH_SYS COMPOUND): step 1 checks\n"
            "                        if AUTH_SYS is accepted at the root;\n"
            "                        step 2 sends PUTROOTFH + SECINFO_NO_NAME\n"
            "                        and reports what flavors the server\n"
            "                        advertises and whether --sec is present.\n"
            "                        Exits without attempting Kerberos setup.\n"
            "  --stress              Run all iterations even after failures,\n"
            "                        count by symbolic error code, and report\n"
            "                        per-code totals at the end.  Useful for\n"
            "                        finding intermittent server-side bugs and\n"
            "                        for hammering the RPCSEC_GSS replay cache\n"
            "                        with a churning seq_num on a single context.\n"
            "  --verbose             Show GSS exchange details\n"
            "\n"
            "Diagnostic options:\n"
            "  --diagnose            Run local pre-flight krb5 checks and exit\n"
            "  --print-error-table   Print the krb5 error taxonomy and exit\n"
            "  --krb5-trace FILE     Set KRB5_TRACE to FILE for libkrb5 tracing.\n"
            "                        Captures THIS process's libkrb5 calls only;\n"
            "                        will NOT capture rpc.gssd or gssproxy.  For\n"
            "                        kernel-side traces use:\n"
            "                          rpcdebug -m rpc -s auth\n"
            "                          journalctl -u rpc-gssd -f\n"
            "\n"
            "Tests RPCSEC_GSS (RFC 2203) Kerberos 5 context establishment and\n"
            "authenticated NULL RPC calls against an NFS server.  --sec krb5i\n"
            "and --sec krb5p exercise integrity and privacy services per RFC 2203\n"
            "S5.3.2 / S5.3.3 respectively; the default krb5 flavor only proves\n"
            "the authenticator works.\n"
            "\n"
            "Exit status uses the canonical krb5 error taxonomy: 0 on success,\n"
            "100..199 for the dominant failure class, 250 (MIXED) if more than\n"
            "one class fails in the same run.  Run --print-error-table for\n"
            "the full code list.\n",
            prog, prog, prog);
    exit(EXIT_FAILURE);
}

static uint32_t parse_sec_flavor(const char *s, const char *prog)
{
    if (strcmp(s, "krb5")  == 0) return RPCSEC_GSS_SVC_NONE;
    if (strcmp(s, "krb5i") == 0) return RPCSEC_GSS_SVC_INTEG;
    if (strcmp(s, "krb5p") == 0) return RPCSEC_GSS_SVC_PRIV;
    fprintf(stderr,
            "Error: --sec must be one of krb5, krb5i, krb5p (got '%s')\n\n",
            s);
    usage(prog);
    return 0; /* unreachable */
}

static void parse_options(int argc, char **argv, struct options *o)
{
    static const struct option long_opts[] = {
        { "host",             required_argument, NULL, 'H' },
        { "port",             required_argument, NULL, 'p' },
        { "principal",        required_argument, NULL, 'P' },
        { "iterations",       required_argument, NULL, 'i' },
        { "sec",              required_argument, NULL, 'S' },
        { "stress",           no_argument,       NULL, 's' },
        { "verbose",          no_argument,       NULL, 'v' },
        { "diagnose",         no_argument,       NULL, 'D' },
        { "print-error-table",no_argument,       NULL, 'E' },
        { "krb5-trace",       required_argument, NULL, 'T' },
        { "probe-secinfo",    no_argument,       NULL, 'Q' },
        { NULL, 0, NULL, 0 }
    };

    memset(o, 0, sizeof(*o));
    o->o_port       = "2049";
    o->o_iterations = 1;
    o->o_sec        = RPCSEC_GSS_SVC_NONE;  /* default: plain krb5 */

    int ch;
    while ((ch = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'H': o->o_host             = optarg;       break;
        case 'p': o->o_port             = optarg;       break;
        case 'P': o->o_principal        = optarg;       break;
        case 'i': o->o_iterations       = atol(optarg); break;
        case 'S': o->o_sec = parse_sec_flavor(optarg, argv[0]); break;
        case 's': o->o_stress           = 1;            break;
        case 'v': o->o_verbose          = 1;            break;
        case 'D': o->o_diagnose         = 1;            break;
        case 'E': o->o_print_error_table = 1;           break;
        case 'T': o->o_krb5_trace       = optarg;       break;
        case 'Q': o->o_probe_secinfo    = 1;            break;
        default:  usage(argv[0]);
        }
    }

    /* --diagnose and --print-error-table run without a host */
    if (o->o_diagnose || o->o_print_error_table)
        return;

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

    /* Register the krb5 error table into the cross-domain registry
     * before any nfs_error_emit_one or nfs_error_lookup is called. */
    krb5_error_init();

    /*
     * --krb5-trace: enable libkrb5 tracing for THIS process.
     *
     * KRB5_TRACE is read by libkrb5 once per process at the first
     * krb5_init_context() call (which gss_init_sec_context will
     * indirectly trigger), so it must be set before any GSS-API call.
     *
     * This only captures libkrb5 calls made inside this binary.  It
     * does NOT capture rpc.gssd / gssproxy traces, which run in
     * separate processes.  When the failure is in the kernel-side
     * GSS path (mount-time, the daemons answer for the kernel) you
     * want `rpcdebug -m rpc -s auth` plus `journalctl -u rpc-gssd`
     * instead of (or in addition to) this flag.
     *
     * The file is appended to, not truncated, so multiple runs
     * accumulate.  Do not delete the file mid-run; libkrb5 keeps an
     * fd open against it for the life of the process.
     *
     * Edge case: if a GSS mechanism plugin linked into this binary calls
     * krb5_init_context from a library constructor (__attribute__
     * ((constructor))), KRB5_TRACE is checked before main() runs and
     * setenv here will be too late for those early calls.  Stock MIT
     * krb5 and the standard gssapi_krb5 plugin do not do this; exotic
     * third-party mech libraries might.  If you need to capture those
     * early calls, set KRB5_TRACE in the shell before invoking the tool.
     */
    if (opts.o_krb5_trace) {
        if (setenv("KRB5_TRACE", opts.o_krb5_trace, 1) != 0) {
            fprintf(stderr, "warning: setenv(KRB5_TRACE) failed: %s\n",
                    strerror(errno));
        } else if (opts.o_verbose) {
            printf("krb5 trace: writing libkrb5 trace to %s\n",
                   opts.o_krb5_trace);
        }
    }

    /* --diagnose: run pre-flight krb5 checks and exit. */
    if (opts.o_diagnose) {
        diag_init_krb5();
        return diag_run(DIAG_DOMAIN_KRB5);
    }

    /* --print-error-table: dump the canonical krb5 taxonomy and exit. */
    if (opts.o_print_error_table) {
        nfs_error_print_table("krb5");
        return NFS_ERR_OK;
    }

    /* --probe-secinfo: run the NFSv4 SECINFO probe and exit without
     * attempting Kerberos context setup.  Useful for diagnosing
     * NFS4ERR_WRONGSEC failures before committing a Kerberos ticket. */
    if (opts.o_probe_secinfo)
        return probe_secinfo(&opts);

    /* Build default principal "nfs@HOST" if not specified */
    char default_principal[512];
    if (!opts.o_principal) {
        snprintf(default_principal, sizeof(default_principal),
                 "nfs@%s", opts.o_host);
        opts.o_principal = default_principal;
    }

    const char *sec_label = (opts.o_sec == RPCSEC_GSS_SVC_NONE)  ? "krb5"
                          : (opts.o_sec == RPCSEC_GSS_SVC_INTEG) ? "krb5i"
                          : (opts.o_sec == RPCSEC_GSS_SVC_PRIV)  ? "krb5p"
                                                                 : "?";
    printf("nfs_krb5_test: %s:%s principal=%s sec=%s\n",
           opts.o_host, opts.o_port, opts.o_principal, sec_label);

    /* --- Connect --- */
    char errbuf[512];
    int fd = tcp_connect_host(opts.o_host, opts.o_port, errbuf, sizeof(errbuf));
    if (fd < 0) {
        /* TCP-level failure is not part of the krb5 taxonomy proper;
         * report verbosely and use NFS_ERR_INTERNAL as the exit code
         * so callers can still distinguish "before krb5 even started"
         * from "krb5 classified failure". */
        fprintf(stderr, "connect: %s\n", errbuf);
        return NFS_ERR_INTERNAL;
    }

    /* --- GSS context establishment --- */
    struct gss_ctx gc;
    memset(&gc, 0, sizeof(gc));
    gss_ctx_defaults_init(&gc);
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
        int code = krb5_emit_gss_failure("gss_import_name",
                                         maj_stat, min_stat,
                                         GSS_C_NO_OID);
        close(fd);
        return code;
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
            int code = krb5_emit_gss_failure("gss_init_sec_context",
                                             maj_stat, min_stat,
                                             gc.gc_mech);
            gss_release_buffer(&min_stat, &out_token);
            gss_release_name(&min_stat, &gc.gc_svc_name);
            close(fd);
            return code;
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
                /* Build-side overflow is a tool bug, not a krb5
                 * problem -- emit INTERNAL and bail. */
                nfs_error_emit_one(stderr, NFS_ERR_INTERNAL,
                                   "build_gss_init_call: buffer overflow");
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return NFS_ERR_INTERNAL;
            }
            if (rpc_writen(fd, call_buf, call_len) != (ssize_t)call_len) {
                /* TCP write failure mid-handshake -- transport error,
                 * not a krb5 classification.  Use INTERNAL. */
                fprintf(stderr, "write INIT call: %s\n", strerror(errno));
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return NFS_ERR_INTERNAL;
            }

            /* Read INIT reply */
            ssize_t rlen = read_rpc_reply(fd, reply_buf, sizeof(reply_buf),
                                           errbuf, sizeof(errbuf));
            if (rlen < 0) {
                /* Server hung up or short read -- typically a krb5
                 * rejection that the server didn't send a structured
                 * RPCSEC_GSS reject for.  Tag it as RPCSEC_GSS_FAILED. */
                nfs_error_emit_one(stderr, KRB5_ERR_RPCSEC_GSS_FAILED,
                                   errbuf);
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return KRB5_ERR_RPCSEC_GSS_FAILED;
            }

            int done = parse_gss_init_reply(reply_buf, (size_t)rlen, xid,
                                             &gc, &in_token, errbuf,
                                             sizeof(errbuf));
            if (done < 0) {
                /* Reply parsed but not as a valid RPCSEC_GSS resok --
                 * server returned an RPC reject or a malformed body. */
                nfs_error_emit_one(stderr, KRB5_ERR_RPCSEC_BAD_CRED,
                                   errbuf);
                gss_release_name(&min_stat, &gc.gc_svc_name);
                close(fd);
                return KRB5_ERR_RPCSEC_BAD_CRED;
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

    /* --- DATA NULL calls ---
     *
     * Two modes:
     *
     *   Default (no --stress): bail on the first failure and exit
     *   with that failure's symbolic code.  Best for one-shot
     *   diagnostic runs.
     *
     *   --stress: keep iterating regardless of failures.  Track
     *   per-code counts in stress_fail_by_code[] (krb5 codes 100..199
     *   indexed offset-100), transport / tool bugs in
     *   stress_fail_internal (NFS_ERR_INTERNAL = 255), and anything
     *   that doesn't fit either bucket in stress_fail_unclassified.
     *   After the loop, emit one [ERROR SYMBOL] block per non-zero code
     *   and compute the canonical exit code: NFS_ERR_OK if no failures,
     *   the single dominant krb5 code if exactly one class failed,
     *   NFS_ERR_MIXED if more than one.  Useful for catching
     *   intermittent server-side bugs and replay-cache thrash where
     *   seq_num churn under load surfaces RPCSEC_REPLAY or
     *   RPCSEC_CTXPROBLEM after some N successful calls.
     */
    int result_code = NFS_ERR_OK;
    long stress_ok = 0;
    long stress_fail_internal = 0;
    long stress_fail_unclassified = 0;       /* codes outside known ranges */
    long stress_fail_by_code[100] = { 0 };  /* index = code - 100 */

    for (long i = 0; i < opts.o_iterations; i++) {
        xid++;
        int iter_code = NFS_ERR_OK;

        size_t call_len = build_gss_data_null(call_buf, sizeof(call_buf),
                                               xid, NFS_PROGRAM, NFS_VERSION_4,
                                               &gc, opts.o_sec,
                                               errbuf, sizeof(errbuf));
        if (call_len == 0) {
            iter_code = KRB5_ERR_GSS_CONTEXT_EXPIRED;
            goto record;
        }
        if (rpc_writen(fd, call_buf, call_len) != (ssize_t)call_len) {
            snprintf(errbuf, sizeof(errbuf),
                     "write DATA NULL: %s", strerror(errno));
            iter_code = NFS_ERR_INTERNAL;
            goto record;
        }

        ssize_t rlen = read_rpc_reply(fd, reply_buf, sizeof(reply_buf),
                                       errbuf, sizeof(errbuf));
        if (rlen < 0) {
            iter_code = KRB5_ERR_RPCSEC_CTXPROBLEM;
            goto record;
        }
        if (parse_data_reply_verifier(reply_buf, (size_t)rlen, xid,
                                       &gc, opts.o_sec,
                                       errbuf, sizeof(errbuf)) < 0) {
            iter_code = KRB5_ERR_GSS_BAD_MIC;
            goto record;
        }

        /* Success */
        stress_ok++;
        if (opts.o_verbose)
            printf("  DATA NULL [%ld]: OK (seq=%u)\n", i + 1, gc.gc_seq_num);
        else if (!opts.o_stress)
            printf("  NULL call %ld/%ld OK\n", i + 1, opts.o_iterations);
        continue;

record:
        if (iter_code >= 100 && iter_code < 200)
            stress_fail_by_code[iter_code - 100]++;
        else if (iter_code == NFS_ERR_INTERNAL)
            stress_fail_internal++;
        else
            /*
             * Code outside {0, 100..199, NFS_ERR_INTERNAL}.  Should
             * not happen today; tracked separately so future additions
             * that forget to update this switch are visible rather than
             * silently inflating stress_fail_internal.
             */
            stress_fail_unclassified++;

        if (!opts.o_stress) {
            /* Default mode: emit immediately and bail. */
            nfs_error_emit_one(stderr, iter_code, errbuf);
            result_code = iter_code;
            break;
        }
        /* Stress mode: silently accumulate; the per-code summary
         * gets emitted after the loop.  Print one short progress
         * line per failure for visibility. */
        if (opts.o_verbose)
            fprintf(stderr, "  iter %ld: code=%d %s\n",
                    i + 1, iter_code, errbuf);
    }

    /*
     * Stress mode: emit per-code [ERROR SYMBOL] blocks and compute
     * the canonical aggregate exit code.  Skipped in default mode
     * (which already set result_code on the first failure above).
     */
    if (opts.o_stress) {
        printf("\nstress: %ld attempts, %ld ok\n",
               (long)opts.o_iterations, stress_ok);
        int distinct = 0;
        int single_code = NFS_ERR_OK;
        for (int idx = 0; idx < 100; idx++) {
            if (stress_fail_by_code[idx] == 0)
                continue;
            int code = 100 + idx;
            char ctx[64];
            snprintf(ctx, sizeof(ctx),
                     "%ld stress failure%s",
                     stress_fail_by_code[idx],
                     stress_fail_by_code[idx] == 1 ? "" : "s");
            nfs_error_emit_one(stderr, code, ctx);
            distinct++;
            single_code = code;
        }
        if (stress_fail_internal > 0) {
            char ctx[64];
            snprintf(ctx, sizeof(ctx),
                     "%ld transport / internal failure%s",
                     stress_fail_internal,
                     stress_fail_internal == 1 ? "" : "s");
            nfs_error_emit_one(stderr, NFS_ERR_INTERNAL, ctx);
            distinct++;
            single_code = NFS_ERR_INTERNAL;
        }
        if (stress_fail_unclassified > 0) {
            fprintf(stderr,
                    "[ERROR ?]  (%ld unclassified failure%s -- "
                    "unknown exit code; please file a bug)\n",
                    stress_fail_unclassified,
                    stress_fail_unclassified == 1 ? "" : "s");
            distinct++;
            single_code = NFS_ERR_INTERNAL;
        }
        if (distinct == 0)
            result_code = NFS_ERR_OK;
        else if (distinct == 1)
            result_code = single_code;
        else
            result_code = NFS_ERR_MIXED;
    }

    /* --- Cleanup --- */
    gss_buffer_desc out_tok2 = GSS_C_EMPTY_BUFFER;
    gss_delete_sec_context(&min_stat, &gc.gc_ctx, &out_tok2);
    gss_release_buffer(&min_stat, &out_tok2);
    gss_release_name(&min_stat, &gc.gc_svc_name);
    if (in_token.value)
        free(in_token.value);
    close(fd);

    if (result_code == NFS_ERR_OK)
        printf("PASS\n");
    else
        printf("FAIL\n");

    return result_code;
}
