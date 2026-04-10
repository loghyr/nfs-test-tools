/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * krb5_error.h -- Kerberos / RPCSEC_GSS entry into the canonical NFS
 * error taxonomy.
 *
 * The full descriptor table lives in krb5_error.c and registers into
 * the generic registry from nfs_error.{h,c} via krb5_error_init().
 *
 * Phase decomposition (5 phases, mirroring the reviewer's
 * recommendation that we keep symbols fine-grained but the *phase*
 * grouping coarse enough to fit on the report's "Error breakdown"
 * one-liner):
 *
 *   PRE_FLIGHT  -- local environment check (--diagnose-style):
 *                  /etc/krb5.conf, keytab presence and readability,
 *                  presence of nfs/<host>@REALM principal, FQDN
 *                  hostname canonicalization, gssproxy/rpc.gssd
 *                  selection.
 *   KERBEROS    -- libkrb5 / KDC interactions: clock skew, KDC
 *                  unreachable, missing TGT, expired TGT, enctype
 *                  negotiation, principal-form mismatch, kvno
 *                  divergence between keytab and KDC.  Collapses
 *                  what could be three sub-phases (KDC, KEYTAB,
 *                  CCACHE) into one because they all reduce to
 *                  "libkrb5 could not produce a usable ticket".
 *   GSS         -- gss_import_name, gss_init_sec_context,
 *                  gss_get_mic, gss_verify_mic, gss_wrap, gss_unwrap.
 *                  Failure modes that arise inside the GSS-API
 *                  abstraction layer above libkrb5.
 *   RPCSEC_GSS  -- RFC 2203 wire-level rejections from the server:
 *                  CTXPROBLEM, CREDPROBLEM, replay window, wrongsec,
 *                  SECINFO empty, replay-cache file permission.
 *   IDMAP       -- post-auth identity mapping failures: nfsidmap
 *                  domain mismatch, nobody fallback, plugin failure.
 *                  Symptoms typically appear after a successful
 *                  context establishment.
 *
 * Code numbering: 100..199 reserved for the krb5 domain.  Within each
 * phase the codes are numerically grouped with small gaps so new
 * codes can be added without renumbering callers or CI matchers.
 *
 * The cross-domain aggregates NFS_ERR_MIXED (250) and NFS_ERR_INTERNAL
 * (255) from nfs_error.h are also represented as krb5-table entries
 * so nfs_error_lookup() can resolve them when the krb5 table is the
 * only one registered.
 */

#ifndef KRB5_ERROR_H
#define KRB5_ERROR_H

#include "nfs_error.h"

enum krb5_phase {
	KRB5_PHASE_PRE_FLIGHT = 0,
	KRB5_PHASE_KERBEROS = 1,
	KRB5_PHASE_GSS = 2,
	KRB5_PHASE_RPCSEC_GSS = 3,
	KRB5_PHASE_IDMAP = 4,
	KRB5_PHASE_NUM
};

enum krb5_error_code {
	/* Pre-flight (100..119) */
	KRB5_ERR_NO_KRB5_CONF = 100,
	KRB5_ERR_KRB5_CONF_PARSE = 101,
	KRB5_ERR_NO_DEFAULT_REALM = 102,
	KRB5_ERR_NO_KEYTAB_FILE = 103,
	KRB5_ERR_KEYTAB_NOT_READABLE = 104,
	KRB5_ERR_NO_NFS_PRINCIPAL = 105,
	KRB5_ERR_NO_GSSPROXY_OR_GSSD = 106,
	KRB5_ERR_NO_NFSIDMAP = 107,
	KRB5_ERR_HOSTNAME_NOT_FQDN = 108,
	KRB5_ERR_RDNS_MISMATCH = 109,

	/* Kerberos / libkrb5 (120..149) */
	KRB5_ERR_CLOCK_SKEW = 120,
	KRB5_ERR_KDC_UNREACHABLE = 121,
	KRB5_ERR_NO_TGT = 122,
	KRB5_ERR_TGT_EXPIRED = 123,
	KRB5_ERR_TGT_NOT_YET_VALID = 124,
	KRB5_ERR_KEYTAB_NO_PRINCIPAL = 125,
	KRB5_ERR_BAD_ENCTYPE = 126,
	KRB5_ERR_ENCTYPE_NEGOTIATION = 127,
	KRB5_ERR_PRINCIPAL_UNKNOWN = 128,
	KRB5_ERR_PREAUTH_FAILED = 129,
	KRB5_ERR_BAD_KVNO = 130,
	KRB5_ERR_BAD_INTEGRITY = 131,
	KRB5_ERR_PRINCIPAL_FORM = 132,
	KRB5_ERR_NOT_US = 133,
	KRB5_ERR_BAD_REALM = 134,

	/* GSS-API (150..169) */
	KRB5_ERR_GSS_BAD_NAME = 150,
	KRB5_ERR_GSS_BAD_MECH = 151,
	KRB5_ERR_GSS_NO_CRED = 152,
	KRB5_ERR_GSS_DEFECTIVE_TOKEN = 153,
	KRB5_ERR_GSS_DEFECTIVE_CRED = 154,
	KRB5_ERR_GSS_CRED_EXPIRED = 155,
	KRB5_ERR_GSS_CONTEXT_EXPIRED = 156,
	KRB5_ERR_GSS_BAD_MIC = 157,
	KRB5_ERR_GSS_BAD_SIG = 158,
	KRB5_ERR_GSS_INIT_FAILED = 159,

	/* RPCSEC_GSS wire (170..189) */
	KRB5_ERR_RPCSEC_VERS_MISMATCH = 170,
	KRB5_ERR_RPCSEC_BAD_CRED = 171,
	KRB5_ERR_RPCSEC_GSS_FAILED = 172,
	KRB5_ERR_RPCSEC_CTXPROBLEM = 173,
	KRB5_ERR_RPCSEC_CREDPROBLEM = 174,
	KRB5_ERR_RPCSEC_REPLAY = 175,
	KRB5_ERR_REPLAY_CACHE_PERM = 176,
	KRB5_ERR_WRONGSEC = 177,
	KRB5_ERR_SECINFO_EMPTY = 178,
	KRB5_ERR_NULL_REJECTED = 179,

	/* Identity mapping (190..199) */
	KRB5_ERR_IDMAP_DOMAIN_MISMATCH = 190,
	KRB5_ERR_IDMAP_NOBODY = 191,
	KRB5_ERR_IDMAP_PLUGIN_FAILED = 192,
	KRB5_ERR_IDMAPD_NOT_RUNNING = 193,
};

/*
 * krb5_error_init -- register the krb5 table into the cross-domain
 * registry.  Idempotent; safe to call multiple times.  Must be
 * called before any nfs_error_lookup or nfs_error_emit_one with a
 * krb5 code.
 */
void krb5_error_init(void);

#endif /* KRB5_ERROR_H */
