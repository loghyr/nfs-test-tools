/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_error.c -- domain-agnostic error taxonomy registry.
 *
 * See nfs_error.h for the registry contract.  Implementation is
 * deliberately tiny: a fixed-size table of registered domains, linear
 * walk on lookup.  No hash, no dynamic allocation, no thread sync --
 * registration happens once at process start before any worker
 * threads exist, and lookup is read-only thereafter.
 */

#include "nfs_error.h"

#include <stdio.h>
#include <string.h>

/*
 * Maximum number of registered tables.  Bumped only when a new
 * protocol domain is added; not user-configurable.
 */
#define NFS_ERROR_MAX_TABLES 4

static const struct nfs_error_table *s_tables[NFS_ERROR_MAX_TABLES];
static size_t s_n_tables = 0;

int nfs_error_register(const struct nfs_error_table *table)
{
	if (!table)
		return -1;

	/*
     * Idempotent: same pointer twice is a no-op.  Dedup is by pointer
     * identity, not by domain string, because two distinct tables in
     * the same domain (e.g. a test harness mock) must both register.
     * Overflowing NFS_ERROR_MAX_TABLES is a programmer error; callers
     * that hit the -1 return should raise the constant in this file.
     */
	for (size_t i = 0; i < s_n_tables; i++) {
		if (s_tables[i] == table)
			return 0;
	}

	if (s_n_tables >= NFS_ERROR_MAX_TABLES)
		return -1;

	s_tables[s_n_tables++] = table;
	return 0;
}

const struct nfs_error_info *
nfs_error_lookup(int code, const struct nfs_error_table **table_out)
{
	for (size_t t = 0; t < s_n_tables; t++) {
		const struct nfs_error_table *tab = s_tables[t];
		for (size_t i = 0; i < tab->n_entries; i++) {
			if (tab->entries[i].code == code) {
				if (table_out)
					*table_out = tab;
				return &tab->entries[i];
			}
		}
	}
	if (table_out)
		*table_out = NULL;
	return NULL;
}

const char *nfs_error_phase_name(const struct nfs_error_table *table, int phase)
{
	if (!table || !table->phase_names)
		return "?";
	if (phase < 0 || (size_t)phase >= table->n_phases)
		return "?";
	const char *name = table->phase_names[phase];
	return name ? name : "?";
}

void nfs_error_emit_one(FILE *f, int code, const char *context)
{
	const struct nfs_error_table *tab = NULL;
	const struct nfs_error_info *e = nfs_error_lookup(code, &tab);

	if (!f)
		f = stderr;

	if (!e) {
		fprintf(f, "[ERROR ?]  (code=%d, no descriptor)\n", code);
		return;
	}

	if (context && *context)
		fprintf(f, "[ERROR %s]  (%s)\n", e->symbol, context);
	else
		fprintf(f, "[ERROR %s]\n", e->symbol);

	fprintf(f, "    %s\n", e->description);
	fprintf(f, "    Fix: %s\n", e->suggestion);
	if (e->doc_anchor && *e->doc_anchor)
		fprintf(f, "    See: TROUBLESHOOTING.md#%s\n", e->doc_anchor);
	else
		fprintf(f, "    See: TROUBLESHOOTING.md\n");
}

void nfs_error_print_table(const char *domain)
{
	/*
     * Markdown table suitable for inclusion in TROUBLESHOOTING.md.
     * Columns are intentionally narrow so the rendered output stays
     * readable when checked into the docs.
     */
	printf("| Code | Symbol | Domain | Phase | Description | Fix | See |\n");
	printf("|------|--------|--------|-------|-------------|-----|-----|\n");
	for (size_t t = 0; t < s_n_tables; t++) {
		const struct nfs_error_table *tab = s_tables[t];
		if (domain && strcmp(domain, tab->domain) != 0)
			continue;
		for (size_t i = 0; i < tab->n_entries; i++) {
			const struct nfs_error_info *e = &tab->entries[i];
			printf("| %d | `%s` | %s | %s | %s | %s | "
			       "[#%s](#%s) |\n",
			       e->code, e->symbol, tab->domain,
			       nfs_error_phase_name(tab, e->phase),
			       e->description, e->suggestion,
			       e->doc_anchor ? e->doc_anchor : "",
			       e->doc_anchor ? e->doc_anchor : "");
		}
	}
}
