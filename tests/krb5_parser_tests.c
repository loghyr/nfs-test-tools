/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * krb5_parser_tests.c -- offline unit tests for parse_data_reply_verifier.
 *
 * Tests exercise the 13 cases from the review notes:
 *   1.  Valid SVC_NONE NULL reply (no crypto, verf_len=0)
 *   2.  Valid SVC_INTEG NULL reply (mock verify_mic -> GSS_S_COMPLETE)
 *   3.  Valid SVC_PRIV NULL reply  (mock unwrap -> seq_num + conf_state=1)
 *   4.  Truncated databody_integ length
 *   5.  Truncated checksum
 *   6.  Wrong inner seq_num
 *   7.  SVC_INTEG with bad MIC (mock verify_mic -> GSS_S_BAD_SIG)
 *   8.  SVC_PRIV with conf_state=0 forced
 *   9.  Trailing junk after checksum (SVC_INTEG)
 *  10.  Empty body when SVC_INTEG was requested
 *  11.  XID mismatch in reply header
 *  12.  RPC_MSG_DENIED reply (not accepted)
 *  13.  Trailing junk after wrapped token (SVC_PRIV, RFC 2203 S5.3.3)
 *
 * Mock injection:
 *   All tests set verf_len=0 in the reply so the header gss_verify_mic call
 *   is skipped; mock pointers control only the body verification path.
 *   gc.gc_ctx = GSS_C_NO_CONTEXT throughout; mocks ignore the ctx argument.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <gssapi/gssapi.h>

#include "gss_wire.h"
#include "rpc_wire.h"

/* -----------------------------------------------------------------------
 * Test infrastructure
 * --------------------------------------------------------------------- */

static int g_pass = 0;
static int g_fail = 0;

#define RUN_TEST(fn) do {                               \
	int _rc = (fn)();                               \
	if (_rc == 0) {                                 \
		g_pass++;                               \
		printf("PASS: %s\n", #fn);              \
	} else {                                        \
		g_fail++;                               \
		printf("FAIL: %s\n", #fn);              \
	}                                               \
} while (0)

/* -----------------------------------------------------------------------
 * Wire-format builder helpers
 *
 * These build hand-crafted reply buffers that parse_data_reply_verifier
 * reads.  The format follows RFC 2203 / RFC 5531 (ONC RPC).
 * --------------------------------------------------------------------- */

static void put_u32(uint8_t *buf, size_t *pos, uint32_t v)
{
	buf[(*pos)++] = (uint8_t)((v >> 24) & 0xff);
	buf[(*pos)++] = (uint8_t)((v >> 16) & 0xff);
	buf[(*pos)++] = (uint8_t)((v >>  8) & 0xff);
	buf[(*pos)++] = (uint8_t)( v        & 0xff);
}

/* XDR opaque<>: 4-byte length + data + zero-padding to 4-byte boundary */
static void put_opaque(uint8_t *buf, size_t *pos,
		       const uint8_t *data, uint32_t len)
{
	put_u32(buf, pos, len);
	memcpy(buf + *pos, data, len);
	*pos += len;
	uint32_t pad = (4u - (len & 3u)) & 3u;
	memset(buf + *pos, 0, pad);
	*pos += pad;
}

/*
 * build_reply_header -- write the fixed portion of a DATA NULL reply:
 *   xid, RPC_REPLY, RPC_MSG_ACCEPTED, verifier (verf_len bytes),
 *   RPC_SUCCESS.
 *
 * Using verf_len=0 skips the header gss_verify_mic call inside the parser,
 * making structural tests independent of real or mock crypto.
 *
 * Returns the buffer position immediately after accept_stat (= body start).
 */
static size_t build_reply_header(uint8_t *buf,
				 size_t bufsz __attribute__((unused)),
				 uint32_t xid, uint32_t verf_len)
{
	size_t pos = 0;
	put_u32(buf, &pos, xid);
	put_u32(buf, &pos, RPC_REPLY);          /* msg_type = 1 */
	put_u32(buf, &pos, RPC_MSG_ACCEPTED);   /* reply_stat = 0 */
	put_u32(buf, &pos, RPCSEC_GSS);         /* verf_flavor = 6 */
	put_u32(buf, &pos, verf_len);
	if (verf_len > 0) {
		uint32_t padded = (verf_len + 3u) & ~3u;
		memset(buf + pos, 0xAA, padded);    /* dummy MIC bytes */
		pos += padded;
	}
	put_u32(buf, &pos, RPC_SUCCESS);        /* accept_stat = 0 */
	return pos;
}

/* -----------------------------------------------------------------------
 * Mock GSSAPI functions
 * --------------------------------------------------------------------- */

static OM_uint32 mock_verify_ok(OM_uint32 *min_stat,
				gss_ctx_id_t ctx __attribute__((unused)),
				gss_buffer_t msg __attribute__((unused)),
				gss_buffer_t mic __attribute__((unused)),
				gss_qop_t *qop)
{
	*min_stat = 0;
	if (qop)
		*qop = 0;
	return GSS_S_COMPLETE;
}

static OM_uint32 mock_verify_badsig(OM_uint32 *min_stat,
				    gss_ctx_id_t ctx __attribute__((unused)),
				    gss_buffer_t msg __attribute__((unused)),
				    gss_buffer_t mic __attribute__((unused)),
				    gss_qop_t *qop __attribute__((unused)))
{
	*min_stat = 0;
	return GSS_S_BAD_SIG;
}

/*
 * g_mock_unwrap_seq -- seq_num that mock_unwrap_ok places in the plain buffer.
 * Set before each priv-path test.
 */
static uint32_t g_mock_unwrap_seq = 0;

static OM_uint32 mock_unwrap_ok(OM_uint32 *min_stat,
				gss_ctx_id_t ctx __attribute__((unused)),
				gss_buffer_t input __attribute__((unused)),
				gss_buffer_t output,
				int *conf_state,
				gss_qop_t *qop)
{
	uint8_t *p = malloc(4);
	if (!p) {
		*min_stat = 0;
		return GSS_S_FAILURE;
	}
	p[0] = (uint8_t)((g_mock_unwrap_seq >> 24) & 0xff);
	p[1] = (uint8_t)((g_mock_unwrap_seq >> 16) & 0xff);
	p[2] = (uint8_t)((g_mock_unwrap_seq >>  8) & 0xff);
	p[3] = (uint8_t)( g_mock_unwrap_seq        & 0xff);
	output->value  = p;
	output->length = 4;
	*conf_state    = 1;
	if (qop)
		*qop = 0;
	*min_stat = 0;
	return GSS_S_COMPLETE;
}

/* Returns conf_state=0 to exercise the confidentiality check. */
static OM_uint32 mock_unwrap_noconf(OM_uint32 *min_stat,
				    gss_ctx_id_t ctx __attribute__((unused)),
				    gss_buffer_t input __attribute__((unused)),
				    gss_buffer_t output,
				    int *conf_state,
				    gss_qop_t *qop)
{
	uint8_t *p = malloc(4);
	if (!p) {
		*min_stat = 0;
		return GSS_S_FAILURE;
	}
	memset(p, 0, 4);
	output->value  = p;
	output->length = 4;
	*conf_state    = 0;   /* no confidentiality */
	if (qop)
		*qop = 0;
	*min_stat = 0;
	return GSS_S_COMPLETE;
}

/* Paired with mock_unwrap_ok / mock_unwrap_noconf: free the malloc'd plain. */
static OM_uint32 mock_release_free(OM_uint32 *min_stat, gss_buffer_t buf)
{
	*min_stat = 0;
	if (buf && buf->value) {
		free(buf->value);
		buf->value  = NULL;
		buf->length = 0;
	}
	return GSS_S_COMPLETE;
}

/* -----------------------------------------------------------------------
 * Test context initialiser
 * --------------------------------------------------------------------- */

static void test_gc_init(struct gss_ctx *gc, uint32_t seq_num)
{
	memset(gc, 0, sizeof(*gc));
	gc->gc_ctx     = GSS_C_NO_CONTEXT;
	gc->gc_seq_num = seq_num;
	/* gc_handle_len=0, gc_handle zeroed -- handle is empty */
	/* mock pointers left NULL; tests set the ones they need */
}

/* -----------------------------------------------------------------------
 * Test 1: Valid SVC_NONE NULL reply (no crypto)
 *
 * A SVC_NONE reply has no body after accept_stat.  With verf_len=0 there
 * is no MIC to verify, so this test is entirely structural.
 * --------------------------------------------------------------------- */

static int test_svc_none_valid(void)
{
	uint8_t buf[256];
	size_t  body_len = build_reply_header(buf, sizeof(buf), 0x1234u, 0);

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, body_len, 0x1234u, &gc,
					   RPCSEC_GSS_SVC_NONE,
					   errbuf, sizeof(errbuf));
	if (rc != 0)
		printf("  error: %s\n", errbuf);
	return rc;
}

/* -----------------------------------------------------------------------
 * Test 2: Valid SVC_INTEG NULL reply (mock verify_mic -> GSS_S_COMPLETE)
 *
 * Inner body = 4-byte seq_num.  mock_verify_ok accepts any MIC bytes.
 * --------------------------------------------------------------------- */

static int test_svc_integ_valid(void)
{
	uint8_t  buf[256];
	uint32_t seq = 42u;
	size_t   pos = build_reply_header(buf, sizeof(buf), 0xABCDu, 0);

	uint8_t inner[4] = {
		(uint8_t)((seq >> 24) & 0xff),
		(uint8_t)((seq >> 16) & 0xff),
		(uint8_t)((seq >>  8) & 0xff),
		(uint8_t)( seq        & 0xff),
	};
	uint8_t mic[4] = { 0x11, 0x22, 0x33, 0x44 };   /* ignored by mock */
	put_opaque(buf, &pos, inner, 4);   /* opaque databody_integ<> */
	put_opaque(buf, &pos, mic,   4);   /* opaque checksum<> */

	struct gss_ctx gc;
	test_gc_init(&gc, seq);
	gc.gc_verify_mic = mock_verify_ok;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0xABCDu, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc != 0)
		printf("  error: %s\n", errbuf);
	return rc;
}

/* -----------------------------------------------------------------------
 * Test 3: Valid SVC_PRIV NULL reply (mock unwrap -> seq_num + conf_state=1)
 *
 * The wrapped body bytes are arbitrary -- mock_unwrap_ok synthesises the
 * 4-byte seq_num plain text.  mock_release_free reclaims the malloc'd buf.
 * --------------------------------------------------------------------- */

static int test_svc_priv_valid(void)
{
	uint8_t  buf[256];
	uint32_t seq = 42u;
	size_t   pos = build_reply_header(buf, sizeof(buf), 0xDEADu, 0);

	uint8_t wrapped[8] = { 0x55, 0x66, 0x77, 0x88,
				0x99, 0xAA, 0xBB, 0xCC };
	put_opaque(buf, &pos, wrapped, sizeof(wrapped));

	g_mock_unwrap_seq = seq;

	struct gss_ctx gc;
	test_gc_init(&gc, seq);
	gc.gc_unwrap         = mock_unwrap_ok;
	gc.gc_release_buffer = mock_release_free;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0xDEADu, &gc,
					   RPCSEC_GSS_SVC_PRIV,
					   errbuf, sizeof(errbuf));
	if (rc != 0)
		printf("  error: %s\n", errbuf);
	return rc;
}

/* -----------------------------------------------------------------------
 * Test 4: Truncated databody_integ length
 *
 * Only 2 bytes follow accept_stat, not enough for the 4-byte inner_len.
 * --------------------------------------------------------------------- */

static int test_integ_truncated_inner_len(void)
{
	uint8_t buf[256];
	size_t  pos = build_reply_header(buf, sizeof(buf), 0x0001u, 0);
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;   /* 2 bytes -- not a complete uint32 */

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);
	gc.gc_verify_mic = mock_verify_ok;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0001u, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Test 5: Truncated checksum
 *
 * inner_data is complete, but mic_len claims 100 bytes that are not
 * present in the buffer.
 * --------------------------------------------------------------------- */

static int test_integ_truncated_checksum(void)
{
	uint8_t  buf[256];
	uint32_t seq = 1u;
	size_t   pos = build_reply_header(buf, sizeof(buf), 0x0002u, 0);

	uint8_t inner[4] = { 0, 0, 0, (uint8_t)seq };
	put_opaque(buf, &pos, inner, 4);
	put_u32(buf, &pos, 100u);   /* mic_len=100, but no mic bytes follow */

	struct gss_ctx gc;
	test_gc_init(&gc, seq);
	gc.gc_verify_mic = mock_verify_ok;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0002u, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Test 6: Wrong inner seq_num
 *
 * mock_verify_ok accepts the body MIC.  The inner seq_num (99) does not
 * match gc.gc_seq_num (42), which must be caught.
 * --------------------------------------------------------------------- */

static int test_integ_wrong_seq(void)
{
	uint8_t  buf[256];
	uint32_t gc_seq    = 42u;
	uint32_t inner_seq = 99u;   /* deliberate mismatch */
	size_t   pos = build_reply_header(buf, sizeof(buf), 0x0003u, 0);

	uint8_t inner[4] = {
		(uint8_t)((inner_seq >> 24) & 0xff),
		(uint8_t)((inner_seq >> 16) & 0xff),
		(uint8_t)((inner_seq >>  8) & 0xff),
		(uint8_t)( inner_seq        & 0xff),
	};
	uint8_t mic[4] = { 0x00, 0x00, 0x00, 0x00 };
	put_opaque(buf, &pos, inner, 4);
	put_opaque(buf, &pos, mic,   4);

	struct gss_ctx gc;
	test_gc_init(&gc, gc_seq);
	gc.gc_verify_mic = mock_verify_ok;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0003u, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "seq_num mismatch")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Test 7: SVC_INTEG with bad MIC
 *
 * mock_verify_badsig returns GSS_S_BAD_SIG; parser must reject the body.
 * --------------------------------------------------------------------- */

static int test_integ_bad_mic(void)
{
	uint8_t  buf[256];
	uint32_t seq = 42u;
	size_t   pos = build_reply_header(buf, sizeof(buf), 0x0004u, 0);

	uint8_t inner[4] = {
		(uint8_t)((seq >> 24) & 0xff),
		(uint8_t)((seq >> 16) & 0xff),
		(uint8_t)((seq >>  8) & 0xff),
		(uint8_t)( seq        & 0xff),
	};
	uint8_t mic[4] = { 0xBA, 0xD0, 0xBA, 0xD0 };
	put_opaque(buf, &pos, inner, 4);
	put_opaque(buf, &pos, mic,   4);

	struct gss_ctx gc;
	test_gc_init(&gc, seq);
	gc.gc_verify_mic = mock_verify_badsig;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0004u, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "gss_verify_mic")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Test 8: SVC_PRIV with conf_state=0 forced
 *
 * mock_unwrap_noconf returns conf_state=0; the parser must reject the
 * unwrapped body with an appropriate error.
 * --------------------------------------------------------------------- */

static int test_priv_no_conf(void)
{
	uint8_t buf[256];
	size_t  pos = build_reply_header(buf, sizeof(buf), 0x0005u, 0);

	uint8_t wrapped[4] = { 0x01, 0x02, 0x03, 0x04 };
	put_opaque(buf, &pos, wrapped, sizeof(wrapped));

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);
	gc.gc_unwrap         = mock_unwrap_noconf;
	gc.gc_release_buffer = mock_release_free;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0005u, &gc,
					   RPCSEC_GSS_SVC_PRIV,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "confidentiality")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Test 9: Trailing junk after checksum
 *
 * A valid SVC_INTEG reply with 4 extra bytes appended after the checksum.
 * Per RFC 2203 S5.3.2 the parser must reject this.  This is the body-
 * consumption bug identified in the second-pass review.
 * --------------------------------------------------------------------- */

static int test_integ_trailing_junk(void)
{
	uint8_t  buf[256];
	uint32_t seq = 7u;
	size_t   pos = build_reply_header(buf, sizeof(buf), 0x0006u, 0);

	uint8_t inner[4] = { 0, 0, 0, (uint8_t)seq };
	uint8_t mic[4]   = { 0xAA, 0xBB, 0xCC, 0xDD };
	put_opaque(buf, &pos, inner, 4);
	put_opaque(buf, &pos, mic,   4);
	/* append junk after the valid, correctly-padded checksum */
	buf[pos++] = 0xFF;
	buf[pos++] = 0xFF;
	buf[pos++] = 0xFF;
	buf[pos++] = 0xFF;

	struct gss_ctx gc;
	test_gc_init(&gc, seq);
	gc.gc_verify_mic = mock_verify_ok;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0006u, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "trailing")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Test 10: Empty body when SVC_INTEG was requested
 *
 * No bytes follow accept_stat.  The parser must fail when it cannot read
 * the mandatory databody_integ length field.
 * --------------------------------------------------------------------- */

static int test_integ_empty_body(void)
{
	uint8_t buf[256];
	size_t  body_len = build_reply_header(buf, sizeof(buf), 0x0007u, 0);
	/* no body follows */

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);
	gc.gc_verify_mic = mock_verify_ok;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, body_len, 0x0007u, &gc,
					   RPCSEC_GSS_SVC_INTEG,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "missing databody_integ")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * test_wrong_xid
 *
 * Build a valid SVC_NONE reply with xid=0x1111 but ask the parser to
 * validate it against expected_xid=0x2222.  The parser must reject it.
 * --------------------------------------------------------------------- */

static int test_wrong_xid(void)
{
	uint8_t buf[256];
	size_t  body_len = build_reply_header(buf, sizeof(buf), 0x1111u, 0);

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, body_len, 0x2222u, &gc,
					   RPCSEC_GSS_SVC_NONE,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "xid")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * test_denied_reply
 *
 * Construct a reply with reply_stat=RPC_MSG_DENIED (1).  The parser
 * must reject it since only RPC_MSG_ACCEPTED (0) is valid here.
 * --------------------------------------------------------------------- */

static int test_denied_reply(void)
{
	uint8_t buf[256];
	size_t  pos = 0;
	put_u32(buf, &pos, 0x0042u);        /* xid */
	put_u32(buf, &pos, RPC_REPLY);      /* msg_type = 1 */
	put_u32(buf, &pos, 1u);             /* reply_stat = RPC_MSG_DENIED */

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, pos, 0x0042u, &gc,
					   RPCSEC_GSS_SVC_NONE,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "reply")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * test_priv_trailing_junk
 *
 * Build a valid SVC_PRIV reply then append 4 extra bytes after the
 * wrapped token.  The RFC 2203 S5.3.3 trailing-junk check (added to
 * gss_wire.c) must reject it.
 * --------------------------------------------------------------------- */

static int test_priv_trailing_junk(void)
{
	uint8_t buf[512];
	size_t  body_len = build_reply_header(buf, sizeof(buf), 0x000Bu, 0);

	/* databody_priv opaque: seq_num (4 bytes) wrapped as opaque */
	uint8_t plain[4];
	size_t  pp = 0;
	put_u32(plain, &pp, 1u);            /* seq_num matches gc_seq_num */

	put_opaque(buf, &body_len, plain, (uint32_t)pp);

	/* append 4 bytes of trailing junk -- must be rejected */
	put_u32(buf, &body_len, 0xDEADBEEFu);

	struct gss_ctx gc;
	test_gc_init(&gc, 1u);
	gc.gc_unwrap     = mock_unwrap_ok;
	gc.gc_release    = mock_release_free;
	g_mock_unwrap_seq = 1u;

	char errbuf[256] = { 0 };
	int rc = parse_data_reply_verifier(buf, body_len, 0x000Bu, &gc,
					   RPCSEC_GSS_SVC_PRIV,
					   errbuf, sizeof(errbuf));
	if (rc == 0) {
		printf("  expected failure but got success\n");
		return -1;
	}
	if (!strstr(errbuf, "trailing")) {
		printf("  wrong error: %s\n", errbuf);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int main(void)
{
	RUN_TEST(test_svc_none_valid);
	RUN_TEST(test_svc_integ_valid);
	RUN_TEST(test_svc_priv_valid);
	RUN_TEST(test_integ_truncated_inner_len);
	RUN_TEST(test_integ_truncated_checksum);
	RUN_TEST(test_integ_wrong_seq);
	RUN_TEST(test_integ_bad_mic);
	RUN_TEST(test_priv_no_conf);
	RUN_TEST(test_integ_trailing_junk);
	RUN_TEST(test_integ_empty_body);
	RUN_TEST(test_wrong_xid);
	RUN_TEST(test_denied_reply);
	RUN_TEST(test_priv_trailing_junk);

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
