/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tls_error.h -- canonical NFS-over-TLS failure taxonomy.
 *
 * Single source of truth for the failure modes the tool can detect.
 * Each enum value has:
 *
 *   - a stable numeric code (the tool's exit status when only one
 *     class of failure occurred -- multiple classes return EX_MIXED)
 *   - a short symbolic name suitable for log output and CI assertions
 *   - a one-line description suitable for the troubleshooting doc
 *   - a phase (which of the four RFC 9289 phases the failure belongs to)
 *
 * The phase classification mirrors nfs_tls_test's `Error breakdown`
 * line: tcp / probe / handshake / rpc.  The PRE_FLIGHT phase is for
 * --diagnose failures that happen before any network IO.
 */

#ifndef TLS_ERROR_H
#define TLS_ERROR_H

#include <stddef.h>
#include <stdio.h>

enum tls_phase {
    TLS_PHASE_PRE_FLIGHT = 0,  /* local environment check */
    TLS_PHASE_TCP        = 1,  /* TCP connect */
    TLS_PHASE_PROBE      = 2,  /* AUTH_TLS NULL probe */
    TLS_PHASE_HANDSHAKE  = 3,  /* TLS handshake (ALPN, cert, version) */
    TLS_PHASE_RPC        = 4,  /* post-handshake NULL RPC */
    TLS_PHASE_NUM
};

/*
 * Stable error codes.  These are returned via the exit status when a
 * single failure class dominates a run, and printed alongside text
 * messages so CI tooling can match on the symbolic name.
 *
 * Numeric values are deliberately spaced (10, 20, 30, ...) so new
 * codes can be added between existing ones without renumbering.
 */
enum tls_error_code {
    TLS_ERR_OK                    =  0,

    /* Pre-flight (--diagnose) */
    TLS_ERR_KERNEL_TOO_OLD        = 10,
    TLS_ERR_NO_SUNRPC_TLS_CONFIG  = 11,
    TLS_ERR_NO_TLS_MODULE         = 12,
    TLS_ERR_NO_TLSHD              = 13,
    TLS_ERR_TLSHD_NOT_RUNNING     = 14,
    TLS_ERR_OPENSSL_TOO_OLD       = 15,

    /* TCP phase */
    TLS_ERR_TCP_REFUSED           = 20,
    TLS_ERR_TCP_TIMEOUT           = 21,
    TLS_ERR_TCP_HOST_NOT_FOUND    = 22,

    /* AUTH_TLS probe phase */
    TLS_ERR_PROBE_REJECTED        = 30,
    TLS_ERR_PROBE_MALFORMED_REPLY = 31,
    TLS_ERR_PROBE_NO_STARTTLS     = 32,

    /* TLS handshake phase */
    TLS_ERR_HANDSHAKE_FAILED      = 40,
    TLS_ERR_CERT_EXPIRED          = 41,
    TLS_ERR_CERT_NOT_YET_VALID    = 42,
    TLS_ERR_CERT_UNTRUSTED        = 43,
    TLS_ERR_CERT_HOSTNAME         = 44,
    TLS_ERR_CERT_REVOKED          = 45,
    TLS_ERR_CERT_KEY_MISMATCH     = 46,
    TLS_ERR_ALPN_MISMATCH         = 47,
    TLS_ERR_TLS_VERSION_TOO_LOW   = 48,
    TLS_ERR_SAN_MISSING           = 49,
    TLS_ERR_NO_PEER_CERT          = 50,

    /* Post-handshake RPC phase */
    TLS_ERR_RPC_FAILED            = 60,
    TLS_ERR_RPC_TIMEOUT           = 61,

    /* Kernel TLS counters incremented during a passing run */
    TLS_ERR_KTLS_DECRYPT_ERROR    = 70,
    TLS_ERR_KTLS_REKEY_ERROR      = 71,
    TLS_ERR_KTLS_NO_PAD_VIOLATION = 72,

    /* Generic and aggregate */
    TLS_ERR_MIXED                 = 90,  /* multiple classes failed */
    TLS_ERR_INTERNAL              = 99,  /* tool bug, not server bug */
};

/*
 * Description record for an error code.  The set of records is
 * defined once in tls_error.c and exposed via tls_error_lookup().
 */
struct tls_error_info {
    enum tls_error_code code;
    enum tls_phase      phase;
    const char         *symbol;       /* e.g. "CERT_EXPIRED" */
    const char         *description;  /* one-line human-readable */
    const char         *suggestion;   /* one-line fix hint */
    const char         *doc_anchor;   /* TROUBLESHOOTING.md anchor,
                                       * e.g. "cert_expired", or NULL
                                       * to fall back to the phase
                                       * section anchor */
};

/*
 * tls_error_lookup -- look up the descriptor for an error code.
 * Returns NULL if the code is unknown.
 */
const struct tls_error_info *tls_error_lookup(enum tls_error_code code);

/*
 * tls_error_phase_name -- short name for a phase ("tcp", "probe",
 * "handshake", "rpc", "pre-flight").
 */
const char *tls_error_phase_name(enum tls_phase phase);

/*
 * tls_error_print_table -- print the full taxonomy as a markdown
 * table.  Useful for generating the "Common Errors" section of
 * TROUBLESHOOTING.md without manual sync; called by
 * `nfs_tls_test --print-error-table`.
 */
void tls_error_print_table(void);

/*
 * tls_error_emit_one -- pretty-print a single error to f, including
 * the symbolic name, description, suggested fix, and a pointer to
 * the matching section in TROUBLESHOOTING.md.
 *
 * If context != NULL it is appended in parentheses after the symbol
 * (e.g. "(42 failures across 4 workers)").
 *
 * Format:
 *   [ERROR CERT_EXPIRED]  (42 failures)
 *       Server certificate has expired
 *       Fix: Renew the server certificate
 *       See: TROUBLESHOOTING.md#cert_expired
 */
void tls_error_emit_one(FILE *f, enum tls_error_code code,
                        const char *context);

/*
 * tls_error_default_for_phase -- return the canonical "summary" error
 * code for a phase.  Used by nfs_tls_test when only a per-phase failure
 * count is available and a single representative code must be chosen.
 *
 *   PRE_FLIGHT -> TLS_ERR_KERNEL_TOO_OLD
 *   TCP        -> TLS_ERR_TCP_REFUSED
 *   PROBE      -> TLS_ERR_PROBE_REJECTED
 *   HANDSHAKE  -> TLS_ERR_HANDSHAKE_FAILED
 *   RPC        -> TLS_ERR_RPC_FAILED
 *
 * Returns TLS_ERR_INTERNAL for an unknown phase.
 */
enum tls_error_code tls_error_default_for_phase(enum tls_phase phase);

#endif /* TLS_ERROR_H */
