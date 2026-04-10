/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tls_error.h -- TLS-domain entry into the canonical NFS error
 * taxonomy.
 *
 * The full descriptor table lives in tls_error.c and is registered
 * into the generic registry in nfs_error.{h,c} via tls_error_init().
 *
 * The numeric codes in `enum tls_error_code` and the phase enum
 * `enum tls_phase` are stable identifiers used by callers (and as
 * the program exit status) -- the registry stores them as plain
 * ints and resolves the phase name through the registered table's
 * phase_names array, so adding new phases here only requires
 * updating tls_error.c.
 *
 * The wrapper functions below are kept as a thin compatibility
 * facade so existing call sites in nfs_tls_test.c don't need to
 * change.  New code should call the nfs_error_* functions directly.
 *
 * Phases for the TLS taxonomy:
 *   PRE_FLIGHT  -- local environment check (--diagnose)
 *   TCP         -- TCP connect
 *   PROBE       -- AUTH_TLS NULL probe
 *   HANDSHAKE   -- TLS handshake (ALPN, cert, version)
 *   RPC         -- post-handshake NULL RPC
 *
 * Code numbering: gaps of 10 within each phase so new codes can be
 * added without renumbering callers or CI.
 */

#ifndef TLS_ERROR_H
#define TLS_ERROR_H

#include <stddef.h>
#include <stdio.h>

#include "nfs_error.h"

enum tls_phase {
	TLS_PHASE_PRE_FLIGHT = 0, /* local environment check */
	TLS_PHASE_TCP = 1, /* TCP connect */
	TLS_PHASE_PROBE = 2, /* AUTH_TLS NULL probe */
	TLS_PHASE_HANDSHAKE = 3, /* TLS handshake (ALPN, cert, version) */
	TLS_PHASE_RPC = 4, /* post-handshake NULL RPC */
	TLS_PHASE_NUM
};

enum tls_error_code {
	TLS_ERR_OK = 0,

	/* Pre-flight (--diagnose) */
	TLS_ERR_KERNEL_TOO_OLD = 10,
	TLS_ERR_NO_SUNRPC_TLS_CONFIG = 11,
	TLS_ERR_NO_TLS_MODULE = 12,
	TLS_ERR_NO_TLSHD = 13,
	TLS_ERR_TLSHD_NOT_RUNNING = 14,
	TLS_ERR_OPENSSL_TOO_OLD = 15,

	/* TCP phase */
	TLS_ERR_TCP_REFUSED = 20,
	TLS_ERR_TCP_TIMEOUT = 21,
	TLS_ERR_TCP_HOST_NOT_FOUND = 22,

	/* AUTH_TLS probe phase */
	TLS_ERR_PROBE_REJECTED = 30,
	TLS_ERR_PROBE_MALFORMED_REPLY = 31,
	TLS_ERR_PROBE_NO_STARTTLS = 32,

	/* TLS handshake phase */
	TLS_ERR_HANDSHAKE_FAILED = 40,
	TLS_ERR_CERT_EXPIRED = 41,
	TLS_ERR_CERT_NOT_YET_VALID = 42,
	TLS_ERR_CERT_UNTRUSTED = 43,
	TLS_ERR_CERT_HOSTNAME = 44,
	TLS_ERR_CERT_REVOKED = 45,
	TLS_ERR_CERT_KEY_MISMATCH = 46,
	TLS_ERR_ALPN_MISMATCH = 47,
	TLS_ERR_TLS_VERSION_TOO_LOW = 48,
	TLS_ERR_SAN_MISSING = 49,
	TLS_ERR_NO_PEER_CERT = 50,

	/* Post-handshake RPC phase */
	TLS_ERR_RPC_FAILED = 60,
	TLS_ERR_RPC_TIMEOUT = 61,

	/* Kernel TLS counters incremented during a passing run */
	TLS_ERR_KTLS_DECRYPT_ERROR = 70,
	TLS_ERR_KTLS_REKEY_ERROR = 71,
	TLS_ERR_KTLS_NO_PAD_VIOLATION = 72,

	/* Generic and aggregate.  Numerically distinct from the new
     * cross-domain NFS_ERR_MIXED / NFS_ERR_INTERNAL aggregates so
     * the original TLS exit codes are preserved verbatim. */
	TLS_ERR_MIXED = 90,
	TLS_ERR_INTERNAL = 99,
};

/*
 * tls_error_init -- register the TLS table into the generic registry.
 *
 * Must be called once at process startup before any tls_error_*
 * lookup or emit.  Idempotent: subsequent calls are no-ops.
 */
void tls_error_init(void);

/*
 * Backward-compatible wrappers around nfs_error_*.  These let
 * existing call sites in nfs_tls_test.c stay unchanged.
 */
const struct nfs_error_info *tls_error_lookup(enum tls_error_code code);
const char *tls_error_phase_name(enum tls_phase phase);
void tls_error_print_table(void);
void tls_error_emit_one(FILE *f, enum tls_error_code code, const char *context);

/*
 * tls_error_default_for_phase -- canonical "summary" code for a phase.
 *
 *   PRE_FLIGHT -> TLS_ERR_KERNEL_TOO_OLD
 *   TCP        -> TLS_ERR_TCP_REFUSED
 *   PROBE      -> TLS_ERR_PROBE_REJECTED
 *   HANDSHAKE  -> TLS_ERR_HANDSHAKE_FAILED
 *   RPC        -> TLS_ERR_RPC_FAILED
 *
 * Returns TLS_ERR_INTERNAL for unknown phases.
 */
enum tls_error_code tls_error_default_for_phase(enum tls_phase phase);

#endif /* TLS_ERROR_H */
