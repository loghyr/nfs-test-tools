/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * diag.c -- shared diagnose registry primitives.
 *
 * Domain-agnostic verdict helpers and the fixed-size check registry
 * walked by diag_run().  Extracted from diagnose.c so that the
 * primitives can be linked into binaries that don't want OpenSSL
 * (e.g. nfs_krb5_test), since diagnose.c proper carries the TLS
 * check set and pulls in the openssl headers.
 *
 * No external dependencies beyond libc.  All registration is
 * static-pointer-based; no dynamic allocation, no thread sync (the
 * registry is filled before any worker threads spawn).
 */

#include "diagnose.h"

#include <stdio.h>

void diag_emit(const char *check, enum diag_verdict v, const char *detail)
{
	printf("DIAG: %s: %s: %s\n", check, diag_verdict_str(v), detail);
}

enum diag_verdict diag_combine(enum diag_verdict a, enum diag_verdict b)
{
	if (a == DIAG_FAIL || b == DIAG_FAIL)
		return DIAG_FAIL;
	if (a == DIAG_WARN || b == DIAG_WARN)
		return DIAG_WARN;
	return DIAG_PASS;
}

const char *diag_verdict_str(enum diag_verdict v)
{
	switch (v) {
	case DIAG_PASS:
		return "PASS";
	case DIAG_WARN:
		return "WARN";
	case DIAG_FAIL:
		return "FAIL";
	}
	return "?";
}

/*
 * Maximum number of registered checks.  Sized to comfortably hold
 * the TLS + krb5 check sets without dynamic allocation.
 */
#define DIAG_MAX_CHECKS 32

static const struct diag_check *s_checks[DIAG_MAX_CHECKS];
static size_t s_n_checks = 0;

int diag_register(const struct diag_check *check)
{
	if (!check || !check->run || !check->name)
		return -1;

	/* Idempotent: same pointer twice is a no-op. */
	for (size_t i = 0; i < s_n_checks; i++) {
		if (s_checks[i] == check)
			return 0;
	}
	if (s_n_checks >= DIAG_MAX_CHECKS)
		return -1;
	s_checks[s_n_checks++] = check;
	return 0;
}

/*
 * domain_label -- printable string for the most common domain mask
 * values.  Used in the report header so users know which set of
 * checks ran without parsing the per-line output.
 */
static const char *domain_label(unsigned domains)
{
	if (domains == DIAG_DOMAIN_TLS)
		return "NFS-over-TLS";
	if (domains == DIAG_DOMAIN_KRB5)
		return "NFS-over-Kerberos";
	if (domains == DIAG_DOMAIN_ALL)
		return "NFS (all domains)";
	return "NFS";
}

int diag_run(unsigned domains)
{
	enum diag_verdict total = DIAG_PASS;
	int matched = 0;

	printf("nfs-test-tools diagnose: pre-flight checks for %s\n",
	       domain_label(domains));
	printf("------------------------------------------------------------\n");

	for (size_t i = 0; i < s_n_checks; i++) {
		const struct diag_check *c = s_checks[i];
		if ((c->domains & domains) == 0)
			continue;
		matched++;
		total = diag_combine(total, c->run());
	}

	printf("------------------------------------------------------------\n");
	if (matched == 0) {
		printf("Overall: ?  (no checks registered for the requested "
		       "domain mask 0x%x)\n",
		       domains);
		return DIAG_WARN;
	}
	printf("Overall: %s\n", diag_verdict_str(total));
	return (int)total;
}
