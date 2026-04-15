/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * gss_wire.c -- RPCSEC_GSS wire-format builders and parsers.
 *
 * Implements the wire-format helpers declared in gss_wire.h.  See that
 * header for the mock injection contract used by unit tests.
 */

#include "gss_wire.h"
#include "rpc_wire.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <gssapi/gssapi.h>

/* -----------------------------------------------------------------------
 * Production-default initialiser
 * --------------------------------------------------------------------- */

void gss_ctx_defaults_init(struct gss_ctx *gc)
{
	gc->gc_verify_mic = gss_verify_mic;
	gc->gc_unwrap = gss_unwrap;
	gc->gc_release_buffer = gss_release_buffer;
}

/* -----------------------------------------------------------------------
 * XDR opaque helper
 * --------------------------------------------------------------------- */

/*
 * rpc_put_opaque -- write XDR opaque<>: 4-byte length + data + zero padding
 * to a 4-byte boundary.  Returns 1 on success, 0 on overflow.
 */
int rpc_put_opaque(uint8_t *buf, size_t bufsz, size_t *pos, const uint8_t *data,
		   uint32_t len)
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

/* -----------------------------------------------------------------------
 * build_gss_data_null
 * --------------------------------------------------------------------- */

/*
 * build_gss_data_null -- build an RPCSEC_GSS DATA NULL call.
 *
 * Service flavor handling per RFC 2203:
 *
 *   RPCSEC_GSS_SVC_NONE  (krb5)
 *     - cred.service = SVC_NONE
 *     - header verifier = gss_get_mic over [xid .. end-of-cred]
 *     - procedure body  = empty
 *
 *   RPCSEC_GSS_SVC_INTEG (krb5i)  -- RFC 2203 S5.3.2
 *     - cred.service = SVC_INTEG
 *     - header verifier = gss_get_mic over [xid .. end-of-cred]
 *     - procedure body  = rpc_gss_integ_data {
 *           opaque databody_integ<>;  // = u32 seq_num + procedure args
 *           opaque checksum<>;        // = gss_get_mic(databody_integ)
 *       }
 *       For NULL the procedure args are empty so databody_integ is
 *       just the 4-byte seq_num.
 *
 *   RPCSEC_GSS_SVC_PRIV  (krb5p)  -- RFC 2203 S5.3.3
 *     - cred.service = SVC_PRIV
 *     - header verifier = gss_get_mic over [xid .. end-of-cred]
 *     - procedure body  = rpc_gss_priv_data {
 *           opaque databody_priv<>;   // = gss_wrap(seq_num + args)
 *       }
 *       gss_wrap conf_req=1; we verify conf_state on return.
 *
 * Returns total byte count, or 0 on error (errbuf filled).
 */
size_t build_gss_data_null(uint8_t *buf, size_t bufsz, uint32_t xid,
			   uint32_t prog, uint32_t vers, struct gss_ctx *gc,
			   uint32_t service, char *errbuf, size_t errsz)
{
	gc->gc_seq_num++;

	size_t handle_padded = ((size_t)gc->gc_handle_len + 3u) & ~(size_t)3u;
	uint32_t cred_body_len = (uint32_t)(4 + 4 + 4 + 4 + 4 + handle_padded);

	size_t pos = 0;
	size_t marker_pos = pos;
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))
		goto overflow;

	/* Record the start of the call header (xid offset = pos now = 4) */
	size_t header_start = pos;

	if (!rpc_put_u32(buf, bufsz, &pos, xid))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, RPC_CALL))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, 2u))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, prog))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, vers))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, NFS_PROC_NULL))
		goto overflow;

	/* Credential */
	if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, cred_body_len))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_VERSION))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS_DATA))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, gc->gc_seq_num))
		goto overflow;
	if (!rpc_put_u32(buf, bufsz, &pos, service))
		goto overflow;
	if (!rpc_put_opaque(buf, bufsz, &pos, gc->gc_handle, gc->gc_handle_len))
		goto overflow;

	/* Record end of header for MIC computation */
	size_t header_end = pos;

	/* Verifier: gss_get_mic over [header_start, header_end).
	 * Same for all three service flavors. */
	gss_buffer_desc msg_buf;
	msg_buf.value = buf + header_start;
	msg_buf.length = header_end - header_start;

	gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
	OM_uint32 min_stat;
	OM_uint32 maj_stat = gss_get_mic(&min_stat, gc->gc_ctx,
					 GSS_C_QOP_DEFAULT, &msg_buf, &mic_buf);
	if (maj_stat != GSS_S_COMPLETE) {
		snprintf(errbuf, errsz, "gss_get_mic on header: maj=%u min=%u",
			 maj_stat, min_stat);
		return 0;
	}

	/* Write RPCSEC_GSS verifier with the MIC token as body */
	if (!rpc_put_u32(buf, bufsz, &pos, RPCSEC_GSS)) {
		gss_release_buffer(&min_stat, &mic_buf);
		goto overflow;
	}
	if (!rpc_put_opaque(buf, bufsz, &pos, (const uint8_t *)mic_buf.value,
			    (uint32_t)mic_buf.length)) {
		gss_release_buffer(&min_stat, &mic_buf);
		goto overflow;
	}
	gss_release_buffer(&min_stat, &mic_buf);

	/* Procedure body, branching on service flavor.
	 *
	 * For NULL, the "procedure args" are zero bytes, so the inner
	 * databody is just the 4-byte big-endian seq_num. */
	if (service == RPCSEC_GSS_SVC_NONE) {
		/* No body */
	} else if (service == RPCSEC_GSS_SVC_INTEG) {
		uint8_t inner[4];
		size_t inner_pos = 0;
		/* sizeof(inner)==4; rpc_put_u32 cannot fail here, but check
		 * for parity with every other call site in this function. */
		if (!rpc_put_u32(inner, sizeof(inner), &inner_pos,
				 gc->gc_seq_num))
			goto overflow;

		gss_buffer_desc inner_buf = { .length = inner_pos,
					      .value = inner };
		gss_buffer_desc int_mic = GSS_C_EMPTY_BUFFER;
		maj_stat = gss_get_mic(&min_stat, gc->gc_ctx, GSS_C_QOP_DEFAULT,
				       &inner_buf, &int_mic);
		if (maj_stat != GSS_S_COMPLETE) {
			snprintf(errbuf, errsz,
				 "gss_get_mic on integ databody: maj=%u min=%u",
				 maj_stat, min_stat);
			return 0;
		}

		/* opaque databody_integ<> */
		if (!rpc_put_opaque(buf, bufsz, &pos, inner,
				    (uint32_t)inner_pos)) {
			gss_release_buffer(&min_stat, &int_mic);
			goto overflow;
		}
		/* opaque checksum<> */
		if (!rpc_put_opaque(buf, bufsz, &pos, int_mic.value,
				    (uint32_t)int_mic.length)) {
			gss_release_buffer(&min_stat, &int_mic);
			goto overflow;
		}
		gss_release_buffer(&min_stat, &int_mic);
	} else if (service == RPCSEC_GSS_SVC_PRIV) {
		uint8_t inner[4];
		size_t inner_pos = 0;
		/* sizeof(inner)==4; rpc_put_u32 cannot fail here, but check
		 * for parity with every other call site in this function. */
		if (!rpc_put_u32(inner, sizeof(inner), &inner_pos,
				 gc->gc_seq_num))
			goto overflow;

		gss_buffer_desc inner_buf = { .length = inner_pos,
					      .value = inner };
		gss_buffer_desc wrapped = GSS_C_EMPTY_BUFFER;
		int conf_state = 0;
		maj_stat = gss_wrap(&min_stat, gc->gc_ctx, 1 /* conf_req */,
				    GSS_C_QOP_DEFAULT, &inner_buf, &conf_state,
				    &wrapped);
		if (maj_stat != GSS_S_COMPLETE) {
			snprintf(errbuf, errsz,
				 "gss_wrap on priv databody: maj=%u min=%u",
				 maj_stat, min_stat);
			return 0;
		}
		if (!conf_state) {
			gss_release_buffer(&min_stat, &wrapped);
			snprintf(errbuf, errsz,
				 "gss_wrap returned without confidentiality "
				 "(server cipher does not support encryption)");
			return 0;
		}

		/* opaque databody_priv<> */
		if (!rpc_put_opaque(buf, bufsz, &pos, wrapped.value,
				    (uint32_t)wrapped.length)) {
			gss_release_buffer(&min_stat, &wrapped);
			goto overflow;
		}
		gss_release_buffer(&min_stat, &wrapped);
	} else {
		snprintf(errbuf, errsz,
			 "build_gss_data_null: unknown service flavor %u",
			 service);
		return 0;
	}

	/* Fill record marker */
	uint32_t body_len = (uint32_t)(pos - 4);
	size_t mpos = marker_pos;
	if (!rpc_put_u32(buf, bufsz, &mpos, RPC_LAST_FRAG | body_len))
		goto overflow;
	return pos;

overflow:
	snprintf(errbuf, errsz, "build_gss_data_null: buffer overflow");
	return 0;
}

/* -----------------------------------------------------------------------
 * parse_data_reply_verifier
 * --------------------------------------------------------------------- */

/*
 * Dispatch wrappers that call through mock pointers when set, or fall back
 * to the real GSSAPI functions.  These are internal to this file.
 */
static OM_uint32 do_verify_mic(struct gss_ctx *gc, OM_uint32 *min_stat,
			       gss_buffer_t msg, gss_buffer_t mic,
			       gss_qop_t *qop)
{
	if (gc->gc_verify_mic)
		return gc->gc_verify_mic(min_stat, gc->gc_ctx, msg, mic, qop);
	return gss_verify_mic(min_stat, gc->gc_ctx, msg, mic, qop);
}

static OM_uint32 do_unwrap(struct gss_ctx *gc, OM_uint32 *min_stat,
			   gss_buffer_t input, gss_buffer_t output,
			   int *conf_state, gss_qop_t *qop)
{
	if (gc->gc_unwrap)
		return gc->gc_unwrap(min_stat, gc->gc_ctx, input, output,
				     conf_state, qop);
	return gss_unwrap(min_stat, gc->gc_ctx, input, output, conf_state, qop);
}

static OM_uint32 do_release_buffer(struct gss_ctx *gc, OM_uint32 *min_stat,
				   gss_buffer_t buf)
{
	if (gc->gc_release_buffer)
		return gc->gc_release_buffer(min_stat, buf);
	return gss_release_buffer(min_stat, buf);
}

/*
 * parse_data_reply_verifier -- parse a DATA NULL reply and verify the
 * RPCSEC_GSS verifier (gss_verify_mic over the 4-byte seq_num).
 *
 * Returns 0 on success, -1 on error.
 */
int parse_data_reply_verifier(const uint8_t *body, size_t body_len,
			      uint32_t expected_xid, struct gss_ctx *gc,
			      uint32_t service, char *errbuf, size_t errsz)
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
			 "DATA reply: unexpected xid=%u msg=%u stat=%u", xid,
			 msg_type, reply_stat);
		return -1;
	}

	if (!rpc_get_u32(body, body_len, &pos, &verf_flavor) ||
	    !rpc_get_u32(body, body_len, &pos, &verf_len)) {
		snprintf(errbuf, errsz, "DATA reply: short verifier header");
		return -1;
	}

	/*
	 * Reply header verifier: gss_verify_mic over 4 big-endian seq_num
	 * bytes.  RFC 2203 §5.3.1-5.3.3 require this verifier for every
	 * RPCSEC_GSS DATA reply regardless of service flavor (SVC_NONE,
	 * SVC_INTEG, SVC_PRIV).  Reject any reply whose verifier flavor is
	 * not RPCSEC_GSS or whose verifier body is empty -- either would
	 * let an unauthenticated reply be accepted under a GSS session.
	 */
	if (verf_flavor != RPCSEC_GSS) {
		snprintf(errbuf, errsz,
			 "DATA reply: verifier flavor %u (expected RPCSEC_GSS=%u)",
			 verf_flavor, RPCSEC_GSS);
		return -1;
	}
	if (verf_len == 0) {
		snprintf(errbuf, errsz,
			 "DATA reply: RPCSEC_GSS verifier is empty "
			 "(RFC 2203 §5.3 requires a MIC)");
		return -1;
	}
	if (pos + verf_len > body_len) {
		snprintf(errbuf, errsz, "DATA reply: verifier body truncated");
		return -1;
	}
	{
		gss_buffer_desc mic_buf;
		mic_buf.value = (void *)(body + pos);
		mic_buf.length = verf_len;

		uint8_t seq_buf[4];
		size_t sq = 0;
		if (!rpc_put_u32(seq_buf, 4, &sq, gc->gc_seq_num)) {
			snprintf(errbuf, errsz, "DATA reply: seq_buf overflow");
			return -1;
		}

		gss_buffer_desc msg_buf;
		msg_buf.value = seq_buf;
		msg_buf.length = 4;

		OM_uint32 min_stat, qop_state;
		OM_uint32 maj_stat = do_verify_mic(gc, &min_stat, &msg_buf,
						   &mic_buf, &qop_state);
		if (maj_stat != GSS_S_COMPLETE) {
			snprintf(errbuf, errsz,
				 "gss_verify_mic on reply verifier: "
				 "maj=%u min=%u",
				 maj_stat, min_stat);
			return -1;
		}
	}

	size_t verf_padded = ((size_t)verf_len + 3u) & ~(size_t)3u;
	if (!rpc_skip(body_len, &pos, verf_padded)) {
		snprintf(errbuf, errsz, "DATA reply: verifier skip failed");
		return -1;
	}

	if (!rpc_get_u32(body, body_len, &pos, &accept_stat) ||
	    accept_stat != RPC_SUCCESS) {
		snprintf(errbuf, errsz, "DATA reply: accept_stat %u",
			 accept_stat);
		return -1;
	}

	/*
	 * Reply procedure body, branching on service flavor.  For NULL
	 * the procedure results are empty, so the inner body should
	 * decode to a 4-byte seq_num matching gc->gc_seq_num.
	 */
	if (service == RPCSEC_GSS_SVC_NONE) {
		/* No body to parse. */
		return 0;
	}

	if (service == RPCSEC_GSS_SVC_INTEG) {
		/*
		 * rpc_gss_integ_data {
		 *   opaque databody_integ<>;
		 *   opaque checksum<>;
		 * }
		 */
		uint32_t inner_len;
		if (!rpc_get_u32(body, body_len, &pos, &inner_len)) {
			snprintf(errbuf, errsz,
				 "krb5i reply: missing databody_integ length");
			return -1;
		}
		if (pos + inner_len > body_len) {
			snprintf(errbuf, errsz,
				 "krb5i reply: databody_integ truncated "
				 "(len=%u)",
				 inner_len);
			return -1;
		}
		const uint8_t *inner_p = body + pos;
		size_t inner_padded = ((size_t)inner_len + 3u) & ~(size_t)3u;
		if (!rpc_skip(body_len, &pos, inner_padded)) {
			snprintf(errbuf, errsz,
				 "krb5i reply: databody padding short");
			return -1;
		}

		uint32_t mic_len;
		if (!rpc_get_u32(body, body_len, &pos, &mic_len)) {
			snprintf(errbuf, errsz,
				 "krb5i reply: missing checksum length");
			return -1;
		}
		if (pos + mic_len > body_len) {
			snprintf(errbuf, errsz,
				 "krb5i reply: checksum truncated (len=%u)",
				 mic_len);
			return -1;
		}
		gss_buffer_desc inner_buf = { .length = inner_len,
					      .value = (void *)inner_p };
		gss_buffer_desc chk_buf = { .length = mic_len,
					    .value = (void *)(body + pos) };
		OM_uint32 min_stat, qop_state;
		OM_uint32 maj_stat = do_verify_mic(gc, &min_stat, &inner_buf,
						   &chk_buf, &qop_state);
		if (maj_stat != GSS_S_COMPLETE) {
			snprintf(errbuf, errsz,
				 "krb5i reply: gss_verify_mic on databody "
				 "failed maj=%u min=%u",
				 maj_stat, min_stat);
			return -1;
		}

		/* RFC 2203 S5.3.2: after the checksum there must be no
		 * further data.  A noncompliant server appending trailing
		 * bytes would otherwise pass silently. */
		size_t mic_padded = ((size_t)mic_len + 3u) & ~(size_t)3u;
		size_t expected_end = pos + mic_padded;
		if (expected_end != body_len) {
			snprintf(errbuf, errsz,
				 "krb5i reply: %zu trailing byte%s after "
				 "checksum",
				 body_len - pos,
				 (body_len - pos) == 1 ? "" : "s");
			return -1;
		}

		/* Verify the inner seq_num matches. */
		if (inner_len < 4) {
			snprintf(errbuf, errsz,
				 "krb5i reply: databody too short for seq_num");
			return -1;
		}
		size_t sp = 0;
		uint32_t reply_seq;
		if (!rpc_get_u32(inner_p, inner_len, &sp, &reply_seq)) {
			snprintf(errbuf, errsz,
				 "krb5i reply: seq_num read failed");
			return -1;
		}
		if (reply_seq != gc->gc_seq_num) {
			snprintf(errbuf, errsz,
				 "krb5i reply: seq_num mismatch "
				 "(got %u expected %u)",
				 reply_seq, gc->gc_seq_num);
			return -1;
		}
		return 0;
	}

	if (service == RPCSEC_GSS_SVC_PRIV) {
		/*
		 * rpc_gss_priv_data {
		 *   opaque databody_priv<>;   // = gss_wrap(seq_num + results)
		 * }
		 */
		uint32_t wrapped_len;
		if (!rpc_get_u32(body, body_len, &pos, &wrapped_len)) {
			snprintf(errbuf, errsz,
				 "krb5p reply: missing databody_priv length");
			return -1;
		}
		if (pos + wrapped_len > body_len) {
			snprintf(errbuf, errsz,
				 "krb5p reply: databody_priv truncated "
				 "(len=%u)",
				 wrapped_len);
			return -1;
		}
		/* RFC 2203 S5.3.3: after the wrapped token there must be no
		 * further data.  A noncompliant server appending trailing
		 * bytes would otherwise pass silently. */
		size_t wrapped_padded = ((size_t)wrapped_len + 3u) & ~(size_t)3u;
		if (pos + wrapped_padded != body_len) {
			snprintf(errbuf, errsz,
				 "krb5p reply: %zu trailing byte%s after "
				 "databody_priv",
				 body_len - pos,
				 (body_len - pos) == 1 ? "" : "s");
			return -1;
		}
		gss_buffer_desc wrapped = { .length = wrapped_len,
					    .value = (void *)(body + pos) };
		gss_buffer_desc plain = GSS_C_EMPTY_BUFFER;
		OM_uint32 min_stat;
		int conf_state = 0;
		gss_qop_t qop_state = 0;
		OM_uint32 maj_stat = do_unwrap(gc, &min_stat, &wrapped, &plain,
					       &conf_state, &qop_state);
		if (maj_stat != GSS_S_COMPLETE) {
			snprintf(errbuf, errsz,
				 "krb5p reply: gss_unwrap failed "
				 "maj=%u min=%u",
				 maj_stat, min_stat);
			return -1;
		}
		if (!conf_state) {
			do_release_buffer(gc, &min_stat, &plain);
			snprintf(errbuf, errsz,
				 "krb5p reply: gss_unwrap returned no "
				 "confidentiality "
				 "(server did not encrypt the body)");
			return -1;
		}
		if (plain.length < 4) {
			do_release_buffer(gc, &min_stat, &plain);
			snprintf(errbuf, errsz,
				 "krb5p reply: unwrapped body too short "
				 "for seq_num");
			return -1;
		}
		size_t sp = 0;
		uint32_t reply_seq;
		if (!rpc_get_u32(plain.value, plain.length, &sp, &reply_seq)) {
			do_release_buffer(gc, &min_stat, &plain);
			snprintf(errbuf, errsz,
				 "krb5p reply: seq_num read failed");
			return -1;
		}
		do_release_buffer(gc, &min_stat, &plain);
		if (reply_seq != gc->gc_seq_num) {
			snprintf(errbuf, errsz,
				 "krb5p reply: seq_num mismatch "
				 "(got %u expected %u)",
				 reply_seq, gc->gc_seq_num);
			return -1;
		}
		return 0;
	}

	snprintf(errbuf, errsz, "DATA reply: unknown service flavor %u",
		 service);
	return -1;
}
