/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * rpc_wire.h -- Minimal ONC RPC wire format helpers.
 *
 * Implements just enough of RFC 5531 (ONC RPC) to send a NULL call and
 * parse the reply, plus AUTH_TLS (RFC 9289) and RPCSEC_GSS (RFC 2203)
 * credential constants.
 *
 * All fields are big-endian on the wire.  rpc_put_u32() and rpc_get_u32()
 * handle the byte-order conversion.
 */

#ifndef RPC_WIRE_H
#define RPC_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

/* --- Auth flavor constants (RFC 5531 S8, RFC 9289 S4.1) --- */
#define RPC_AUTH_NONE 0u
#define RPC_AUTH_SYS 1u
#define RPCSEC_GSS 6u
#define RPC_AUTH_TLS 7u /* RFC 9289 S4.1 -- STARTTLS probe credential */

/* --- Message type (RFC 5531 S9) --- */
#define RPC_CALL 0u
#define RPC_REPLY 1u

/* --- Reply status (RFC 5531 S9) --- */
#define RPC_MSG_ACCEPTED 0u
#define RPC_MSG_DENIED 1u

/* --- Accept status (RFC 5531 S9) --- */
#define RPC_SUCCESS 0u
#define RPC_PROG_UNAVAIL 1u
#define RPC_PROG_MISMATCH 2u
#define RPC_PROC_UNAVAIL 3u
#define RPC_GARBAGE_ARGS 4u
#define RPC_SYSTEM_ERR 5u

/* --- NFS program constants --- */
#define NFS_PROGRAM 100003u
#define NFS_VERSION_4 4u
#define NFS_VERSION_3 3u
#define NFS_PROC_NULL 0u

/* --- TCP record marking (RFC 5531 S10) --- */
#define RPC_LAST_FRAG 0x80000000u

/* --- RPCSEC_GSS procedure types (RFC 2203 S5) --- */
#define RPCSEC_GSS_DATA 0u
#define RPCSEC_GSS_INIT 1u
#define RPCSEC_GSS_CONTINUE 2u
#define RPCSEC_GSS_DESTROY 3u

/* --- RPCSEC_GSS service types (RFC 2203 S5) --- */
#define RPCSEC_GSS_SVC_NONE 1u
#define RPCSEC_GSS_SVC_INTEG 2u
#define RPCSEC_GSS_SVC_PRIV 3u

/* --- Buffer helpers --- */

/*
 * rpc_put_u32 -- append a big-endian uint32 to buffer at offset *pos.
 * Returns 1 on success, 0 if buffer would overflow.
 */
static inline int rpc_put_u32(uint8_t *buf, size_t bufsz, size_t *pos,
			      uint32_t val)
{
	if (*pos + 4 > bufsz)
		return 0;
	uint32_t be = htonl(val);
	memcpy(buf + *pos, &be, 4);
	*pos += 4;
	return 1;
}

/*
 * rpc_get_u32 -- read a big-endian uint32 from buffer at offset *pos.
 * Returns 1 on success, 0 if buffer is too short.
 */
static inline int rpc_get_u32(const uint8_t *buf, size_t bufsz, size_t *pos,
			      uint32_t *out)
{
	if (*pos + 4 > bufsz)
		return 0;
	uint32_t be;
	memcpy(&be, buf + *pos, 4);
	*out = ntohl(be);
	*pos += 4;
	return 1;
}

/*
 * rpc_skip -- advance *pos by n bytes.
 * Returns 1 on success, 0 if buffer is too short.
 */
static inline int rpc_skip(size_t bufsz, size_t *pos, size_t n)
{
	if (*pos + n > bufsz)
		return 0;
	*pos += n;
	return 1;
}

/* --- I/O helpers --- */

/*
 * rpc_writen -- write exactly n bytes to fd, retrying on EINTR/short writes.
 * Returns n on success, -1 on error.
 */
#include <unistd.h>
#include <errno.h>

static inline ssize_t rpc_writen(int fd, const void *buf, size_t n)
{
	size_t sent = 0;
	const uint8_t *p = (const uint8_t *)buf;
	while (sent < n) {
		ssize_t r = write(fd, p + sent, n - sent);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)r;
	}
	return (ssize_t)n;
}

/*
 * rpc_readn -- read exactly n bytes from fd, retrying on EINTR/short reads.
 * Returns n on success, 0 on EOF, -1 on error.
 */
static inline ssize_t rpc_readn(int fd, void *buf, size_t n)
{
	size_t got = 0;
	uint8_t *p = (uint8_t *)buf;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return 0; /* EOF */
		got += (size_t)r;
	}
	return (ssize_t)n;
}

/*
 * rpc_build_null_call -- encode a NULL RPC call into buf.
 *
 * Builds: [TCP record marker] [xid] [CALL] [rpcvers=2] [prog] [vers] [proc=0]
 *         [cred.flavor] [cred.len=0] [verf.flavor=0] [verf.len=0]
 *
 * Returns the total byte count written (always 44 for a bare NULL call
 * with empty credentials and verifier), or 0 on buffer overflow.
 */
static inline size_t rpc_build_null_call(uint8_t *buf, size_t bufsz,
					 uint32_t xid, uint32_t prog,
					 uint32_t vers, uint32_t cred_flavor)
{
	/* Body is 10 fields x 4 bytes = 40 bytes */
	const uint32_t body_len = 40;
	size_t pos = 0;

	if (!rpc_put_u32(buf, bufsz, &pos, RPC_LAST_FRAG | body_len))
		return 0;
	/* xid */
	if (!rpc_put_u32(buf, bufsz, &pos, xid))
		return 0;
	/* msg_type = CALL */
	if (!rpc_put_u32(buf, bufsz, &pos, RPC_CALL))
		return 0;
	/* rpcvers = 2 */
	if (!rpc_put_u32(buf, bufsz, &pos, 2u))
		return 0;
	/* prog */
	if (!rpc_put_u32(buf, bufsz, &pos, prog))
		return 0;
	/* vers */
	if (!rpc_put_u32(buf, bufsz, &pos, vers))
		return 0;
	/* proc = NULL (0) */
	if (!rpc_put_u32(buf, bufsz, &pos, NFS_PROC_NULL))
		return 0;
	/* credential: flavor, body length = 0 */
	if (!rpc_put_u32(buf, bufsz, &pos, cred_flavor))
		return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))
		return 0;
	/* verifier: AUTH_NONE, body length = 0 */
	if (!rpc_put_u32(buf, bufsz, &pos, RPC_AUTH_NONE))
		return 0;
	if (!rpc_put_u32(buf, bufsz, &pos, 0u))
		return 0;

	return pos; /* 44 */
}

#endif /* RPC_WIRE_H */
