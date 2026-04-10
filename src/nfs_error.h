/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_error.h -- domain-agnostic error taxonomy registry.
 *
 * Common infrastructure for the per-protocol error tables (currently
 * TLS, soon also Kerberos).  Each protocol provides:
 *
 *   - a const array of `struct nfs_error_info` entries
 *   - a const array of phase-name strings
 *   - a `struct nfs_error_table` describing the above
 *
 * and registers it via nfs_error_register() at process start.  Lookup,
 * emit, and table-print walk all registered tables, so a single binary
 * can speak symbols from any combination of domains without code
 * duplication.
 *
 * Numeric code ranges per the project convention:
 *
 *      0          OK / generic success
 *      1..  9     reserved for cross-domain generic codes
 *     10.. 99     TLS  (RFC 9289 RPC-over-TLS)
 *    100..199     Kerberos / RPCSEC_GSS (RFC 2203)
 *    250          MIXED  -- multiple distinct classes failed
 *    255          INTERNAL -- tool bug, not a server problem
 */

#ifndef NFS_ERROR_H
#define NFS_ERROR_H

#include <stddef.h>
#include <stdio.h>

/*
 * struct nfs_error_info -- one entry in a domain's error table.
 *
 * code   : domain-allocated numeric code, unique across all registered
 *          tables.  Used as the program exit status.
 * phase  : domain-private phase index.  Resolved to a string via the
 *          owning table's phase_names[] array.
 * symbol : short ALL_CAPS identifier suitable for log lines and CI
 *          matching, e.g. "CERT_EXPIRED" or "CLOCK_SKEW".
 * description : one-line human-readable cause.
 * suggestion  : one-line fix hint.
 * doc_anchor  : lowercased TROUBLESHOOTING.md anchor (matches `symbol`
 *               in the existing convention), or NULL to fall back to
 *               the phase section.
 */
struct nfs_error_info {
    int          code;
    int          phase;
    const char  *symbol;
    const char  *description;
    const char  *suggestion;
    const char  *doc_anchor;
};

/*
 * struct nfs_error_table -- one registered protocol's table.
 *
 * domain      : short identifier ("tls", "krb5", ...).  Used by
 *               nfs_error_print_table(domain) to filter, and as the
 *               default subtitle in headed output.
 * entries     : pointer to an array of nfs_error_info.
 * n_entries   : length of entries[].
 * phase_names : array of strings indexed by phase int.  An entry's
 *               phase string is `phase_names[entry->phase]`.
 * n_phases    : length of phase_names[]; bounds-checks the lookup.
 */
struct nfs_error_table {
    const char                       *domain;
    const struct nfs_error_info      *entries;
    size_t                            n_entries;
    const char *const                *phase_names;
    size_t                            n_phases;
};

/*
 * Cross-domain aggregate codes.  Reserved at the top of the numeric
 * range so they don't collide with any per-protocol code.
 */
#define NFS_ERR_OK        0
#define NFS_ERR_MIXED     250
#define NFS_ERR_INTERNAL  255

/*
 * nfs_error_register -- register a per-domain table.
 *
 * Idempotent: calling twice with the same table is a no-op.  Returns
 * 0 on success, -1 if the registry is full (raise NFS_ERROR_MAX_TABLES
 * in nfs_error.c if you ever hit this).
 *
 * The table contents must remain valid for the lifetime of the
 * process; tables are typically file-scope `static const`.
 */
int nfs_error_register(const struct nfs_error_table *table);

/*
 * nfs_error_lookup -- find the descriptor for a numeric code.
 *
 * Walks all registered tables in registration order.  If table_out is
 * non-NULL, *table_out is set to the owning table on success so the
 * caller can resolve the entry's phase via the table's phase_names.
 *
 * Returns NULL if no descriptor matches.
 */
const struct nfs_error_info *
nfs_error_lookup(int code, const struct nfs_error_table **table_out);

/*
 * nfs_error_phase_name -- resolve a phase int to a printable string.
 *
 * Returns "?" if the table is NULL or the phase index is out of range.
 */
const char *nfs_error_phase_name(const struct nfs_error_table *table,
                                 int phase);

/*
 * nfs_error_emit_one -- pretty-print a single descriptor to f.
 *
 * Format:
 *
 *   [ERROR SYMBOL]  (context)
 *       Human-readable description
 *       Fix: suggested fix
 *       See: TROUBLESHOOTING.md#anchor
 *
 * If context is NULL or empty the parenthesised section is omitted.
 * If f is NULL, output goes to stderr.  Unknown codes render with a
 * "?" symbol so callers can never crash on a stale value.
 */
void nfs_error_emit_one(FILE *f, int code, const char *context);

/*
 * nfs_error_print_table -- dump the canonical taxonomy as a markdown
 * table to stdout.  Columns: code, symbol, domain, phase, description,
 * fix, doc anchor.
 *
 * If domain is NULL, all registered tables are dumped concatenated.
 * If domain is non-NULL, only that table is printed (case-sensitive
 * match against table->domain).
 */
void nfs_error_print_table(const char *domain);

#endif /* NFS_ERROR_H */
