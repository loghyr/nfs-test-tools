/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gss_wire.h -- RPCSEC_GSS wire-format builders and parsers.
 *
 * Provides parse_data_reply_verifier() and build_gss_data_null() for use
 * by nfs_krb5_test.  struct gss_ctx carries optional mock function pointers
 * so unit tests can inject synthetic GSS responses without requiring a live
 * Kerberos realm.
 *
 * Mock injection contract:
 *   - NULL in gc_verify_mic / gc_unwrap / gc_release_buffer means "call
 *     the real GSSAPI function".
 *   - Production code must call gss_ctx_defaults_init() after zeroing the
 *     struct to get the real-function behaviour explicitly.
 *   - Tests set only the pointers they need to override, then call
 *     gss_ctx_defaults_init() for the rest (or leave the remainder NULL
 *     and rely on the NULL-fallback in the implementation).
 */

#ifndef GSS_WIRE_H
#define GSS_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include <gssapi/gssapi.h>

/* RPCSEC_GSS protocol version (RFC 2203 S5) */
#define RPCSEC_GSS_VERSION 1u

/* -----------------------------------------------------------------------
 * GSS context state (with mock injection for unit tests)
 * --------------------------------------------------------------------- */

struct gss_ctx {
	gss_ctx_id_t gc_ctx; /* GSS context handle */
	gss_name_t gc_svc_name; /* target service name */
	gss_OID gc_mech; /* negotiated mech (krb5) */
	uint32_t gc_handle_len;
	uint8_t gc_handle[256]; /* RPCSEC_GSS context handle from server */
	uint32_t gc_seq_num; /* last sequence number used for DATA */

	/*
	 * Optional mock injection for unit tests.  When non-NULL,
	 * parse_data_reply_verifier() calls these instead of the real
	 * GSSAPI functions.  Set by gss_ctx_defaults_init() to the real
	 * functions in production.
	 */
	OM_uint32 (*gc_verify_mic)(OM_uint32 *, gss_ctx_id_t, gss_buffer_t,
				   gss_buffer_t, gss_qop_t *);
	OM_uint32 (*gc_unwrap)(OM_uint32 *, gss_ctx_id_t, gss_buffer_t,
			       gss_buffer_t, int *, gss_qop_t *);
	OM_uint32 (*gc_release_buffer)(OM_uint32 *, gss_buffer_t);
};

/*
 * gss_ctx_defaults_init -- set mock pointers to the real GSSAPI functions.
 * Call after zeroing a struct gss_ctx in production code.  Tests leave
 * these NULL or override with mocks as needed.
 */
void gss_ctx_defaults_init(struct gss_ctx *gc);

/* -----------------------------------------------------------------------
 * Wire-format helpers
 * --------------------------------------------------------------------- */

/*
 * rpc_put_opaque -- append an XDR opaque<> (4-byte length + data + padding).
 * Returns 1 on success, 0 on overflow.
 */
int rpc_put_opaque(uint8_t *buf, size_t bufsz, size_t *pos, const uint8_t *data,
		   uint32_t len);

/*
 * build_gss_data_null -- build an RPCSEC_GSS DATA NULL call.
 *
 * Service flavor handling per RFC 2203 S5.3:
 *   RPCSEC_GSS_SVC_NONE  (krb5)  -- header MIC verifier, no body
 *   RPCSEC_GSS_SVC_INTEG (krb5i) -- header MIC + integrity-wrapped body
 *   RPCSEC_GSS_SVC_PRIV  (krb5p) -- header MIC + privacy-wrapped body
 *
 * Returns total byte count, or 0 on error (errbuf filled).
 */
size_t build_gss_data_null(uint8_t *buf, size_t bufsz, uint32_t xid,
			   uint32_t prog, uint32_t vers, struct gss_ctx *gc,
			   uint32_t service, char *errbuf, size_t errsz);

/*
 * parse_data_reply_verifier -- parse a DATA NULL reply and verify the
 * RPCSEC_GSS verifier (MIC over the 4-byte seq_num), then verify the
 * integrity or privacy body if the service flavor requires it.
 *
 * Returns 0 on success, -1 on error (errbuf filled).
 */
int parse_data_reply_verifier(const uint8_t *body, size_t body_len,
			      uint32_t expected_xid, struct gss_ctx *gc,
			      uint32_t service, char *errbuf, size_t errsz);

#endif /* GSS_WIRE_H */
