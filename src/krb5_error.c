/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * krb5_error.c -- canonical NFS-over-Kerberos failure taxonomy.
 *
 * Single source of truth for the Kerberos / RPCSEC_GSS failure modes
 * the tool can detect or classify.  Registers into the generic
 * registry from nfs_error.c via krb5_error_init().
 *
 * Adding a new failure mode:
 *   1. Add a stable numeric value to enum krb5_error_code in
 *      krb5_error.h.  Stay within 100..199 and leave gaps for future
 *      growth within the same phase.
 *   2. Add a descriptor to s_krb5_entries[] below with a doc anchor.
 *   3. Add a `### <SYMBOL>` subsection in TROUBLESHOOTING.md whose
 *      anchor matches the doc_anchor field (lowercased symbol name).
 *
 * The minor-status mapping that turns GSS major/minor pairs into
 * symbolic codes lives in a separate commit (it requires linking
 * libkrb5 headers and is only useful once nfs_krb5_test consumes
 * the symbols at runtime).
 */

#include "krb5_error.h"

#include <stddef.h>

static const char *const s_krb5_phase_names[KRB5_PHASE_NUM] = {
	[KRB5_PHASE_PRE_FLIGHT] = "pre-flight",
	[KRB5_PHASE_KERBEROS] = "kerberos",
	[KRB5_PHASE_GSS] = "gss",
	[KRB5_PHASE_RPCSEC_GSS] = "rpcsec_gss",
	[KRB5_PHASE_IDMAP] = "idmap",
};

static const struct nfs_error_info s_krb5_entries[] = {
	/* ----- Pre-flight ------------------------------------------- */

	{ KRB5_ERR_NO_KRB5_CONF, KRB5_PHASE_PRE_FLIGHT, "NO_KRB5_CONF",
	  "/etc/krb5.conf is missing or unreadable",
	  "Install/restore krb5.conf or set KRB5_CONFIG to its location",
	  "no_krb5_conf" },

	{ KRB5_ERR_KRB5_CONF_PARSE, KRB5_PHASE_PRE_FLIGHT, "KRB5_CONF_PARSE",
	  "/etc/krb5.conf could not be parsed by libkrb5",
	  "Run `klist` to see the libkrb5 parser error and fix the syntax",
	  "krb5_conf_parse" },

	{ KRB5_ERR_NO_DEFAULT_REALM, KRB5_PHASE_PRE_FLIGHT, "NO_DEFAULT_REALM",
	  "krb5.conf has no default_realm set in [libdefaults]",
	  "Add `default_realm = YOUR.REALM` to /etc/krb5.conf [libdefaults]",
	  "no_default_realm" },

	{ KRB5_ERR_NO_KEYTAB_FILE, KRB5_PHASE_PRE_FLIGHT, "NO_KEYTAB_FILE",
	  "/etc/krb5.keytab does not exist",
	  "Generate a keytab containing nfs/<host>@REALM and install it",
	  "no_keytab_file" },

	{ KRB5_ERR_KEYTAB_NOT_READABLE, KRB5_PHASE_PRE_FLIGHT,
	  "KEYTAB_NOT_READABLE",
	  "/etc/krb5.keytab exists but is not readable by the current user",
	  "Check unix permissions AND the SELinux file label "
	  "(should be krb5_keytab_t)",
	  "keytab_not_readable" },

	{ KRB5_ERR_NO_NFS_PRINCIPAL, KRB5_PHASE_PRE_FLIGHT, "NO_NFS_PRINCIPAL",
	  "Keytab has no nfs/<host>@REALM service principal",
	  "Add nfs/<fqdn>@REALM to /etc/krb5.keytab via ktutil or kadmin",
	  "no_nfs_principal" },

	{ KRB5_ERR_NO_GSSPROXY_OR_GSSD, KRB5_PHASE_PRE_FLIGHT,
	  "NO_GSSPROXY_OR_GSSD", "Neither gssproxy nor rpc.gssd is running",
	  "systemctl enable --now gssproxy  (or rpc-gssd on legacy systems)",
	  "no_gssproxy_or_gssd" },

	{ KRB5_ERR_NO_NFSIDMAP, KRB5_PHASE_PRE_FLIGHT, "NO_NFSIDMAP",
	  "nfsidmap binary not installed (NFSv4 id mapping will fail)",
	  "Install the nfs-utils (or libnfsidmap) package", "no_nfsidmap" },

	{ KRB5_ERR_HOSTNAME_NOT_FQDN, KRB5_PHASE_PRE_FLIGHT,
	  "HOSTNAME_NOT_FQDN",
	  "Local hostname is not a fully qualified domain name",
	  "Set hostname to FQDN (hostnamectl set-hostname host.fqdn) so "
	  "the krb5 service principal canonicalises correctly",
	  "hostname_not_fqdn" },

	{ KRB5_ERR_RDNS_MISMATCH, KRB5_PHASE_PRE_FLIGHT, "RDNS_MISMATCH",
	  "Forward and reverse DNS for the local hostname disagree",
	  "Fix DNS so that A/AAAA and PTR resolve consistently, or set "
	  "rdns = false in krb5.conf [libdefaults] (with caveats)",
	  "rdns_mismatch" },

	/* ----- Kerberos / libkrb5 ----------------------------------- */

	{ KRB5_ERR_CLOCK_SKEW, KRB5_PHASE_KERBEROS, "CLOCK_SKEW",
	  "Clock skew vs the KDC exceeds the allowed window (default 5 min)",
	  "Sync system clocks via chrony / systemd-timesyncd on both ends",
	  "clock_skew" },

	{ KRB5_ERR_KDC_UNREACHABLE, KRB5_PHASE_KERBEROS, "KDC_UNREACHABLE",
	  "Could not reach any KDC for the realm",
	  "Check kdc = entries in krb5.conf and firewall to KDC port 88",
	  "kdc_unreachable" },

	{ KRB5_ERR_NO_TGT, KRB5_PHASE_KERBEROS, "NO_TGT",
	  "No Kerberos TGT in the credential cache",
	  "Run `kinit user@REALM` (or check that the machine cred is "
	  "available via gssproxy)",
	  "no_tgt" },

	{ KRB5_ERR_TGT_EXPIRED, KRB5_PHASE_KERBEROS, "TGT_EXPIRED",
	  "User TGT has expired",
	  "Run `kinit -R` to renew or `kinit user@REALM` to re-acquire",
	  "tgt_expired" },

	{ KRB5_ERR_TGT_NOT_YET_VALID, KRB5_PHASE_KERBEROS, "TGT_NOT_YET_VALID",
	  "TGT starttime is in the future",
	  "Almost always clock skew on the issuing KDC; sync clocks",
	  "tgt_not_yet_valid" },

	{ KRB5_ERR_KEYTAB_NO_PRINCIPAL, KRB5_PHASE_KERBEROS,
	  "KEYTAB_NO_PRINCIPAL",
	  "Requested principal not found in the keytab at runtime",
	  "Verify with `klist -k /etc/krb5.keytab | grep nfs/`",
	  "keytab_no_principal" },

	{ KRB5_ERR_BAD_ENCTYPE, KRB5_PHASE_KERBEROS, "BAD_ENCTYPE",
	  "KDC returned KRB5KDC_ERR_ETYPE_NOSUPP -- no acceptable enctype",
	  "Add aes256-cts/aes128-cts to permitted_enctypes and re-key the "
	  "principal in the KDC database",
	  "bad_enctype" },

	{ KRB5_ERR_ENCTYPE_NEGOTIATION, KRB5_PHASE_KERBEROS,
	  "ENCTYPE_NEGOTIATION",
	  "Three-way enctype intersection (keytab, krb5.conf, KDC) is empty",
	  "Inspect `klist -ket /etc/krb5.keytab` and the KDC's allowed "
	  "enctypes; ensure at least one common enctype",
	  "enctype_negotiation" },

	{ KRB5_ERR_PRINCIPAL_UNKNOWN, KRB5_PHASE_KERBEROS, "PRINCIPAL_UNKNOWN",
	  "KDC returned KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN for the service",
	  "Add the principal to the KDC database, or fix the SPN form "
	  "in the client request",
	  "principal_unknown" },

	{ KRB5_ERR_PREAUTH_FAILED, KRB5_PHASE_KERBEROS, "PREAUTH_FAILED",
	  "KDC pre-authentication failed (wrong password, locked account)",
	  "Verify credentials with `kinit user@REALM`; check KDC logs",
	  "preauth_failed" },

	{ KRB5_ERR_BAD_KVNO, KRB5_PHASE_KERBEROS, "BAD_KVNO",
	  "kvno mismatch: the keytab and the KDC database disagree on "
	  "the principal's key version",
	  "Re-key the service principal and re-export the keytab so both "
	  "sides see the same kvno",
	  "bad_kvno" },

	{ KRB5_ERR_BAD_INTEGRITY, KRB5_PHASE_KERBEROS, "BAD_INTEGRITY",
	  "KRB5KRB_AP_ERR_BAD_INTEGRITY -- ticket decryption failed",
	  "Usually a stale keytab on the server, a re-keyed principal, "
	  "or a broken cross-realm trust chain.  Re-export the keytab",
	  "bad_integrity" },

	{ KRB5_ERR_PRINCIPAL_FORM, KRB5_PHASE_KERBEROS, "PRINCIPAL_FORM",
	  "Principal name form mismatch (e.g. nfs/host vs nfs/host.fqdn)",
	  "Use the FQDN form everywhere, and align with what the KDC has "
	  "registered.  Distinct from RDNS_MISMATCH",
	  "principal_form" },

	{ KRB5_ERR_NOT_US, KRB5_PHASE_KERBEROS, "NOT_US",
	  "KRB5_AP_ERR_NOT_US -- server thinks the ticket is for a "
	  "different principal",
	  "Check that hostname canonicalization (rdns, "
	  "dns_canonicalize_hostname) yields the same name on both sides",
	  "not_us" },

	{ KRB5_ERR_BAD_REALM, KRB5_PHASE_KERBEROS, "BAD_REALM",
	  "Cross-realm path is missing or broken",
	  "Verify [domain_realm] mapping and the trust direction in the "
	  "KDC database; check capaths if used",
	  "bad_realm" },

	/* ----- GSS-API ---------------------------------------------- */

	{ KRB5_ERR_GSS_BAD_NAME, KRB5_PHASE_GSS, "GSS_BAD_NAME",
	  "gss_import_name returned GSS_S_BAD_NAME",
	  "Use a service@host or service/host@REALM form acceptable to "
	  "GSS_C_NT_HOSTBASED_SERVICE",
	  "gss_bad_name" },

	{ KRB5_ERR_GSS_BAD_MECH, KRB5_PHASE_GSS, "GSS_BAD_MECH",
	  "Requested GSS mechanism is not available (no krb5 mech?)",
	  "Install the krb5 GSS-API mech (gssapi-krb5) and verify with "
	  "`gss-client` or `gsstest`",
	  "gss_bad_mech" },

	{ KRB5_ERR_GSS_NO_CRED, KRB5_PHASE_GSS, "GSS_NO_CRED",
	  "gss_acquire_cred / gss_init_sec_context returned GSS_S_NO_CRED",
	  "No usable initiator credential -- run kinit, or check the "
	  "machine cred (gssproxy / rpc.gssd)",
	  "gss_no_cred" },

	{ KRB5_ERR_GSS_DEFECTIVE_TOKEN, KRB5_PHASE_GSS, "GSS_DEFECTIVE_TOKEN",
	  "gss_init_sec_context received a defective server token",
	  "Server's GSS implementation produced an unparseable token; "
	  "capture the exchange and inspect server logs",
	  "gss_defective_token" },

	{ KRB5_ERR_GSS_DEFECTIVE_CRED, KRB5_PHASE_GSS, "GSS_DEFECTIVE_CRED",
	  "GSS credential is malformed",
	  "Re-run kinit; if persistent, file a libkrb5 bug",
	  "gss_defective_cred" },

	{ KRB5_ERR_GSS_CRED_EXPIRED, KRB5_PHASE_GSS, "GSS_CRED_EXPIRED",
	  "GSS credential has expired since the context was started",
	  "Renew via kinit -R or re-acquire; long-lived NFS mounts need "
	  "automatic renewal (sssd, k5start)",
	  "gss_cred_expired" },

	{ KRB5_ERR_GSS_CONTEXT_EXPIRED, KRB5_PHASE_GSS, "GSS_CONTEXT_EXPIRED",
	  "GSS security context has expired mid-session",
	  "Server returned RPCSEC_GSS_CTXPROBLEM; client should "
	  "re-establish the context.  If the client doesn't recover, "
	  "check rpc.gssd / gssproxy logs",
	  "gss_context_expired" },

	{ KRB5_ERR_GSS_BAD_MIC, KRB5_PHASE_GSS, "GSS_BAD_MIC",
	  "gss_verify_mic on a server reply MIC failed",
	  "Indicates wire corruption, replay, or a context-vs-key "
	  "desync.  Capture and inspect the GSS exchange",
	  "gss_bad_mic" },

	{ KRB5_ERR_GSS_BAD_SIG, KRB5_PHASE_GSS, "GSS_BAD_SIG",
	  "gss_unwrap reported a bad signature on a wrapped reply",
	  "Same root causes as GSS_BAD_MIC; specific to krb5p (privacy)",
	  "gss_bad_sig" },

	{ KRB5_ERR_GSS_INIT_FAILED, KRB5_PHASE_GSS, "GSS_INIT_FAILED",
	  "gss_init_sec_context failed for an unclassified reason",
	  "Run with --krb5-trace to capture the libkrb5 trace and look "
	  "for the underlying minor-status reason",
	  "gss_init_failed" },

	/* ----- RPCSEC_GSS wire -------------------------------------- */

	{ KRB5_ERR_RPCSEC_VERS_MISMATCH, KRB5_PHASE_RPCSEC_GSS,
	  "RPCSEC_VERS_MISMATCH", "Server rejected RPCSEC_GSS protocol version",
	  "Client and server disagree on RFC 2203 version; should be 1 "
	  "for both.  Check server-side gssd or NFS daemon version",
	  "rpcsec_vers_mismatch" },

	{ KRB5_ERR_RPCSEC_BAD_CRED, KRB5_PHASE_RPCSEC_GSS, "RPCSEC_BAD_CRED",
	  "Server rejected the RPCSEC_GSS credential structure",
	  "Wire-format issue in the credential body or the handle",
	  "rpcsec_bad_cred" },

	{ KRB5_ERR_RPCSEC_GSS_FAILED, KRB5_PHASE_RPCSEC_GSS,
	  "RPCSEC_GSS_FAILED",
	  "Server returned RPCSEC_GSS_FAILED reject reason",
	  "Server's GSS layer rejected the request after parsing.  Check "
	  "server NFS / gssd logs",
	  "rpcsec_gss_failed" },

	{ KRB5_ERR_RPCSEC_CTXPROBLEM, KRB5_PHASE_RPCSEC_GSS,
	  "RPCSEC_CTXPROBLEM",
	  "Server returned RPCSEC_GSS_CTXPROBLEM (context expired or "
	  "unknown)",
	  "Client must re-establish the GSS context.  If this is "
	  "persistent under load, check the server's replay window and "
	  "the client's seq_num generator",
	  "rpcsec_ctxproblem" },

	{ KRB5_ERR_RPCSEC_CREDPROBLEM, KRB5_PHASE_RPCSEC_GSS,
	  "RPCSEC_CREDPROBLEM",
	  "Server returned RPCSEC_GSS_CREDPROBLEM (credentials expired)",
	  "Refresh the underlying Kerberos credentials and retry",
	  "rpcsec_credproblem" },

	{ KRB5_ERR_RPCSEC_REPLAY, KRB5_PHASE_RPCSEC_GSS, "RPCSEC_REPLAY",
	  "Server's RPCSEC_GSS replay window detected a duplicate seq_num",
	  "Concurrent calls on a shared context overflowed the replay "
	  "window (typically 32).  Use a fresh context per worker, or "
	  "throttle concurrency",
	  "rpcsec_replay" },

	{ KRB5_ERR_REPLAY_CACHE_PERM, KRB5_PHASE_RPCSEC_GSS,
	  "REPLAY_CACHE_PERM",
	  "Server-side replay cache file is owned by the wrong uid or "
	  "is not writeable",
	  "Remove /var/tmp/nfs_* (or the krb5 rcache directory) and "
	  "restart rpc.gssd / gssproxy so the cache is recreated with "
	  "correct ownership",
	  "replay_cache_perm" },

	{ KRB5_ERR_WRONGSEC, KRB5_PHASE_RPCSEC_GSS, "WRONGSEC",
	  "Server returned NFS4ERR_WRONGSEC for the requested operation",
	  "The mount used the wrong sec= flavor for this export.  Re-try "
	  "via SECINFO negotiation, or mount with the flavor the server "
	  "advertises",
	  "wrongsec" },

	{ KRB5_ERR_SECINFO_EMPTY, KRB5_PHASE_RPCSEC_GSS, "SECINFO_EMPTY",
	  "SECINFO returned an empty acceptable-flavor list",
	  "Server has no acceptable security flavor for this export.  "
	  "Check server-side sec= configuration and the client's offered "
	  "flavors",
	  "secinfo_empty" },

	{ KRB5_ERR_NULL_REJECTED, KRB5_PHASE_RPCSEC_GSS, "NULL_REJECTED",
	  "Server rejected a NULL RPC over RPCSEC_GSS",
	  "Indicates the server did accept context establishment but "
	  "rejected the first DATA call.  Check sec= flavor agreement "
	  "and server NFS logs",
	  "null_rejected" },

	/* ----- Identity mapping ------------------------------------- */

	{ KRB5_ERR_IDMAP_DOMAIN_MISMATCH, KRB5_PHASE_IDMAP,
	  "IDMAP_DOMAIN_MISMATCH",
	  "Client and server NFSv4 idmap domains disagree",
	  "Set Domain in /etc/idmapd.conf (or /etc/nfs.conf [nfsd] "
	  "v4-idmap-domain) to match the server",
	  "idmap_domain_mismatch" },

	{ KRB5_ERR_IDMAP_NOBODY, KRB5_PHASE_IDMAP, "IDMAP_NOBODY",
	  "Files map to nobody:nobody despite a working krb5 context",
	  "Symptom of IDMAP_DOMAIN_MISMATCH or a broken nfsidmap plugin; "
	  "verify with `nfsidmap -d` and check journalctl for nfsidmap "
	  "errors",
	  "idmap_nobody" },

	{ KRB5_ERR_IDMAP_PLUGIN_FAILED, KRB5_PHASE_IDMAP, "IDMAP_PLUGIN_FAILED",
	  "An nfsidmap plugin (sss / umich_ldap / static) failed to load",
	  "Check /etc/idmapd.conf [Translation] Method= and ensure the "
	  "plugin shared object is installed.  Watch journalctl",
	  "idmap_plugin_failed" },

	{ KRB5_ERR_IDMAPD_NOT_RUNNING, KRB5_PHASE_IDMAP, "IDMAPD_NOT_RUNNING",
	  "rpc.idmapd is not running (legacy NFSv4 client id mapping)",
	  "systemctl enable --now nfs-idmapd  (or migrate to nfsidmap "
	  "plugin model)",
	  "idmapd_not_running" },

	/* ----- Cross-domain aggregates ------------------------------
     *
     * These mirror the same NFS_ERR_MIXED / NFS_ERR_INTERNAL codes
     * declared in nfs_error.h, but are registered as krb5-table
     * entries so that nfs_error_lookup() resolves them when only
     * the krb5 table is registered (i.e. inside nfs_krb5_test).
     * Phase = KRB5_PHASE_NUM (out of range) so the phase column
     * renders as "?".
     */
	{ NFS_ERR_MIXED, KRB5_PHASE_NUM, "MIXED",
	  "Multiple distinct krb5 failure classes occurred in one run",
	  "Inspect the per-phase Error breakdown for details", "mixed" },

	{ NFS_ERR_INTERNAL, KRB5_PHASE_NUM, "INTERNAL",
	  "Tool internal error (out of memory, bad arg, etc.)",
	  "File a bug against nfs-test-tools", "internal" },
};

#define N_KRB5_ENTRIES (sizeof(s_krb5_entries) / sizeof(s_krb5_entries[0]))

static const struct nfs_error_table s_krb5_table = {
	.domain = "krb5",
	.entries = s_krb5_entries,
	.n_entries = N_KRB5_ENTRIES,
	.phase_names = s_krb5_phase_names,
	.n_phases = KRB5_PHASE_NUM,
};

void krb5_error_init(void)
{
	nfs_error_register(&s_krb5_table);
}
