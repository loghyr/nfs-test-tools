/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * tls_error.c -- canonical NFS-over-TLS failure taxonomy.
 *
 * Holds the TLS-domain entries that get registered into the generic
 * registry in nfs_error.c.  This file is the single source of truth
 * for TLS failure descriptors; the runtime error reporting and the
 * troubleshooting documentation both read from this same array, so
 * they cannot drift out of sync.
 *
 * To add a new failure mode:
 *   1. Add an entry to enum tls_error_code in tls_error.h with a
 *      stable numeric value (gaps of 1 within a phase, gaps of 10
 *      between phases).
 *   2. Add a descriptor to s_tls_entries[] below with a doc anchor.
 *   3. Add a `### <symbol>` subsection to TROUBLESHOOTING.md whose
 *      anchor matches the doc_anchor field.
 */

#include "tls_error.h"

#include <stddef.h>

/*
 * TLS phase names, indexed by enum tls_phase.  The registry resolves
 * an entry's phase via this array.
 */
static const char *const s_tls_phase_names[TLS_PHASE_NUM] = {
	[TLS_PHASE_PRE_FLIGHT] = "pre-flight",
	[TLS_PHASE_TCP] = "tcp",
	[TLS_PHASE_PROBE] = "probe",
	[TLS_PHASE_HANDSHAKE] = "handshake",
	[TLS_PHASE_RPC] = "rpc",
};

/*
 * Canonical TLS taxonomy.  When adding a new error mode, add the
 * entry here and the runtime detector and the doc both pick it up
 * via the doc_anchor.
 */
static const struct nfs_error_info s_tls_entries[] = {
	/* Pre-flight */
	{ TLS_ERR_KERNEL_TOO_OLD, TLS_PHASE_PRE_FLIGHT, "KERNEL_TOO_OLD",
	  "Linux kernel below the NFS-over-TLS support floor",
	  "Upgrade to Linux >= 6.12 (or RHEL/Rocky 10)", "kernel_too_old" },

	{ TLS_ERR_NO_SUNRPC_TLS_CONFIG, TLS_PHASE_PRE_FLIGHT,
	  "NO_SUNRPC_TLS_CONFIG", "Kernel was built without CONFIG_SUNRPC_TLS",
	  "Use a kernel built with CONFIG_SUNRPC_TLS=y or =m",
	  "no_sunrpc_tls_config" },

	{ TLS_ERR_NO_TLS_MODULE, TLS_PHASE_PRE_FLIGHT, "NO_TLS_MODULE",
	  "Kernel TLS module not loaded", "modprobe tls", "no_tls_module" },

	{ TLS_ERR_NO_TLSHD, TLS_PHASE_PRE_FLIGHT, "NO_TLSHD",
	  "tlshd binary is not installed",
	  "Install ktls-utils (provides /usr/sbin/tlshd)", "no_tlshd" },

	{ TLS_ERR_TLSHD_NOT_RUNNING, TLS_PHASE_PRE_FLIGHT, "TLSHD_NOT_RUNNING",
	  "tlshd is installed but not running", "systemctl enable --now tlshd",
	  "tlshd_not_running" },

	{ TLS_ERR_OPENSSL_TOO_OLD, TLS_PHASE_PRE_FLIGHT, "OPENSSL_TOO_OLD",
	  "Linked OpenSSL is below 1.1.1 (no TLS 1.3)",
	  "Rebuild against OpenSSL >= 1.1.1", "openssl_too_old" },

	/* TCP */
	{ TLS_ERR_TCP_REFUSED, TLS_PHASE_TCP, "TCP_REFUSED",
	  "Server refused the TCP connection",
	  "Check that nfs-server is running and listening on the port",
	  "tcp_refused" },

	{ TLS_ERR_TCP_TIMEOUT, TLS_PHASE_TCP, "TCP_TIMEOUT",
	  "TCP connect timed out",
	  "Check firewall, network reachability, and server load",
	  "tcp_timeout" },

	{ TLS_ERR_TCP_HOST_NOT_FOUND, TLS_PHASE_TCP, "TCP_HOST_NOT_FOUND",
	  "DNS resolution failed for the server hostname",
	  "Verify --host spelling and DNS configuration",
	  "tcp_host_not_found" },

	/* AUTH_TLS probe */
	{ TLS_ERR_PROBE_REJECTED, TLS_PHASE_PROBE, "PROBE_REJECTED",
	  "Server rejected the AUTH_TLS NULL probe",
	  "Server may not implement RFC 9289 STARTTLS", "probe_rejected" },

	{ TLS_ERR_PROBE_MALFORMED_REPLY, TLS_PHASE_PROBE,
	  "PROBE_MALFORMED_REPLY",
	  "Server reply to AUTH_TLS probe was malformed",
	  "Server's RFC 9289 implementation has a wire-format bug",
	  "probe_malformed_reply" },

	{ TLS_ERR_PROBE_NO_STARTTLS, TLS_PHASE_PROBE, "PROBE_NO_STARTTLS",
	  "Server does not support STARTTLS upgrade",
	  "Enable TLS in the server's NFS config (e.g. tls=y in nfs.conf)",
	  "probe_no_starttls" },

	{ TLS_ERR_TLS_ENABLED_UNEXPECTEDLY, TLS_PHASE_PROBE,
	  "TLS_ENABLED_UNEXPECTEDLY",
	  "Server accepted the AUTH_TLS probe but policy says TLS is not enabled",
	  "Server is violating RFC 9289 S4.1 by answering MSG_ACCEPTED when TLS "
	  "is disabled; it should return MSG_DENIED/AUTH_REJECTEDCRED",
	  "tls_enabled_unexpectedly" },

	/* TLS handshake */
	{ TLS_ERR_HANDSHAKE_FAILED, TLS_PHASE_HANDSHAKE, "HANDSHAKE_FAILED",
	  "TLS handshake failed for an unspecified reason",
	  "Run with --keylog and decrypt the capture in Wireshark",
	  "handshake_failed" },

	{ TLS_ERR_CERT_EXPIRED, TLS_PHASE_HANDSHAKE, "CERT_EXPIRED",
	  "Server certificate has expired", "Renew the server certificate",
	  "cert_expired" },

	{ TLS_ERR_CERT_NOT_YET_VALID, TLS_PHASE_HANDSHAKE, "CERT_NOT_YET_VALID",
	  "Server certificate notBefore is in the future",
	  "Check system clocks on both client and server",
	  "cert_not_yet_valid" },

	{ TLS_ERR_CERT_UNTRUSTED, TLS_PHASE_HANDSHAKE, "CERT_UNTRUSTED",
	  "Server certificate not trusted by the client CA store",
	  "Add the issuing CA to /etc/pki/ca-trust/source/anchors and "
	  "run update-ca-trust (Fedora/RHEL) or update-ca-certificates "
	  "(Debian/Ubuntu)",
	  "cert_untrusted" },

	{ TLS_ERR_CERT_HOSTNAME, TLS_PHASE_HANDSHAKE, "CERT_HOSTNAME",
	  "Server certificate does not match the hostname/IP",
	  "Reissue the cert with the correct CN/SAN entries", "cert_hostname" },

	{ TLS_ERR_CERT_REVOKED, TLS_PHASE_HANDSHAKE, "CERT_REVOKED",
	  "Server certificate has been revoked", "Issue a new certificate",
	  "cert_revoked" },

	{ TLS_ERR_CERT_KEY_MISMATCH, TLS_PHASE_HANDSHAKE, "CERT_KEY_MISMATCH",
	  "Server certificate and private key do not match",
	  "Verify the cert/key pair on the server side", "cert_key_mismatch" },

	{ TLS_ERR_ALPN_MISMATCH, TLS_PHASE_HANDSHAKE, "ALPN_MISMATCH",
	  "Server did not negotiate ALPN 'sunrpc' (RFC 9289 S4)",
	  "Server TLS stack must advertise the 'sunrpc' ALPN protocol",
	  "alpn_mismatch" },

	{ TLS_ERR_TLS_VERSION_TOO_LOW, TLS_PHASE_HANDSHAKE,
	  "TLS_VERSION_TOO_LOW", "Negotiated TLS version is below 1.3",
	  "Configure the server to support and prefer TLS 1.3",
	  "tls_version_too_low" },

	{ TLS_ERR_SAN_MISSING, TLS_PHASE_HANDSHAKE, "SAN_MISSING",
	  "Required subjectAltName entry not present in the cert",
	  "Reissue with the missing IP/DNS in subjectAltName", "san_missing" },

	{ TLS_ERR_NO_PEER_CERT, TLS_PHASE_HANDSHAKE, "NO_PEER_CERT",
	  "Server did not present a certificate at all",
	  "Server has TLS misconfigured or no cert loaded", "no_peer_cert" },

	/* Post-handshake RPC */
	{ TLS_ERR_RPC_FAILED, TLS_PHASE_RPC, "RPC_FAILED",
	  "NULL RPC failed after the TLS channel was established",
	  "Server NFS stack is not responding correctly post-TLS; "
	  "check server logs",
	  "rpc_failed" },

	{ TLS_ERR_RPC_TIMEOUT, TLS_PHASE_RPC, "RPC_TIMEOUT",
	  "NULL RPC timed out after the TLS channel was established",
	  "Server NFS stack is hung or overloaded", "rpc_timeout" },

	/* Kernel TLS counters */
	{ TLS_ERR_KTLS_DECRYPT_ERROR, TLS_PHASE_RPC, "KTLS_DECRYPT_ERROR",
	  "Kernel TLS layer logged a TlsDecryptError during the run",
	  "Indicates corruption, MITM, or kernel TLS bug",
	  "ktls_decrypt_error" },

	{ TLS_ERR_KTLS_REKEY_ERROR, TLS_PHASE_RPC, "KTLS_REKEY_ERROR",
	  "Kernel TLS layer logged a TlsTxRekeyError or TlsRxRekeyError",
	  "TLS 1.3 key update failed; check kernel version",
	  "ktls_rekey_error" },

	{ TLS_ERR_KTLS_NO_PAD_VIOLATION, TLS_PHASE_RPC, "KTLS_NO_PAD_VIOLATION",
	  "Kernel TLS layer logged a TlsRxNoPadViolation",
	  "TLS_RX_EXPECT_NO_PAD mis-prediction; usually benign",
	  "ktls_no_pad_violation" },

	/* Aggregate.  Phase = TLS_PHASE_NUM (out of range) so the phase
     * column renders as "?" -- these are not associated with any
     * single phase. */
	{ TLS_ERR_MIXED, TLS_PHASE_NUM, "MIXED",
	  "Multiple distinct failure classes occurred in one run",
	  "Inspect the per-phase Error breakdown line for details", "mixed" },

	{ TLS_ERR_INTERNAL, TLS_PHASE_NUM, "INTERNAL",
	  "Tool internal error (out of memory, bad arg, etc.)",
	  "File a bug against nfs-test-tools", "internal" },
};

#define N_TLS_ENTRIES (sizeof(s_tls_entries) / sizeof(s_tls_entries[0]))

static const struct nfs_error_table s_tls_table = {
	.domain = "tls",
	.entries = s_tls_entries,
	.n_entries = N_TLS_ENTRIES,
	.phase_names = s_tls_phase_names,
	.n_phases = TLS_PHASE_NUM,
};

void tls_error_init(void)
{
	nfs_error_register(&s_tls_table);
}

/* ----- Backward-compatible wrappers ------------------------------ */

const struct nfs_error_info *tls_error_lookup(enum tls_error_code code)
{
	return nfs_error_lookup((int)code, NULL);
}

const char *tls_error_phase_name(enum tls_phase phase)
{
	return nfs_error_phase_name(&s_tls_table, (int)phase);
}

void tls_error_print_table(void)
{
	nfs_error_print_table("tls");
}

void tls_error_emit_one(FILE *f, enum tls_error_code code, const char *context)
{
	nfs_error_emit_one(f, (int)code, context);
}

enum tls_error_code tls_error_default_for_phase(enum tls_phase phase)
{
	switch (phase) {
	case TLS_PHASE_PRE_FLIGHT:
		return TLS_ERR_KERNEL_TOO_OLD;
	case TLS_PHASE_TCP:
		return TLS_ERR_TCP_REFUSED;
	case TLS_PHASE_PROBE:
		return TLS_ERR_PROBE_REJECTED;
	case TLS_PHASE_HANDSHAKE:
		return TLS_ERR_HANDSHAKE_FAILED;
	case TLS_PHASE_RPC:
		return TLS_ERR_RPC_FAILED;
	default:
		return TLS_ERR_INTERNAL;
	}
}
