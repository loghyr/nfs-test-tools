/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * diagnose.h -- local pre-flight checks for NFS readiness.
 *
 * Encodes the "Pre-flight checks" sections of TROUBLESHOOTING.md as a
 * runnable check list.  Use --diagnose to run before the network test;
 * if any check fails, the network test won't work either.
 *
 * Architecture: a small registry of `struct diag_check` entries, each
 * tagged with a domain bitmask (TLS, KRB5, ...).  Domain-specific
 * sources call diag_register() at startup to add their checks; the
 * driver function diag_run(domain_mask) walks the registry and runs
 * everything that matches.  This keeps TLS-only and Kerberos-only
 * checks out of each other's binaries while sharing the verdict
 * machinery.
 */

#ifndef DIAGNOSE_H
#define DIAGNOSE_H

/*
 * Verdict for a single check or for the overall run.  Numeric values
 * intentionally match the diagnose_run() exit code:
 *   V_PASS = 0   all checks passed
 *   V_FAIL = 1   at least one check failed
 *   V_WARN = 2   at least one check warned, none failed
 */
enum diag_verdict {
    DIAG_PASS = 0,
    DIAG_FAIL = 1,
    DIAG_WARN = 2,
};

/*
 * Domain bitmask.  Each registered check declares one or more domains
 * it belongs to; diag_run takes the same kind of mask and runs the
 * intersection.
 */
#define DIAG_DOMAIN_TLS    (1u << 0)
#define DIAG_DOMAIN_KRB5   (1u << 1)
#define DIAG_DOMAIN_ALL    (DIAG_DOMAIN_TLS | DIAG_DOMAIN_KRB5)

/*
 * struct diag_check -- one entry in the registry.
 *
 * name      : short kebab-case identifier used in the "DIAG: <name>:"
 *             output line.  Stable for CI matchers.
 * domains   : bitmask of which logical domains this check applies to.
 *             A pre-flight check that's useful for both TLS and krb5
 *             (e.g. "is my hostname FQDN?") can set both bits.
 * run       : the check function.  Returns its own verdict and is
 *             expected to call diag_emit() for its result line.
 */
struct diag_check {
    const char       *name;
    unsigned          domains;
    enum diag_verdict (*run)(void);
};

/*
 * diag_register -- add a check to the registry.
 *
 * Pointer must remain valid for the lifetime of the process; entries
 * are typically file-scope `static const`.  Returns 0 on success, -1
 * if the registry is full (raise DIAG_MAX_CHECKS in diagnose.c if you
 * ever hit this -- currently 32).
 *
 * Idempotent on the same pointer.
 */
int diag_register(const struct diag_check *check);

/*
 * diag_emit -- emit one structured result line.
 *
 *   DIAG: <name>: <PASS|FAIL|WARN>: <detail>
 *
 * Called by check functions; exposed in the header so per-domain
 * check files can share the same output convention.
 */
void diag_emit(const char *name, enum diag_verdict v, const char *detail);

/*
 * diag_combine -- worst-of-two combinator: FAIL beats WARN beats PASS.
 *
 * Exposed for check functions that internally aggregate sub-checks.
 */
enum diag_verdict diag_combine(enum diag_verdict a, enum diag_verdict b);

/*
 * diag_verdict_str -- short uppercase label for a verdict ("PASS",
 * "WARN", "FAIL", or "?").  Lifetime is static; do not free.
 */
const char *diag_verdict_str(enum diag_verdict v);

/*
 * diag_run -- run all registered checks whose domain mask intersects
 * `domains`, print a header and footer, and return the overall verdict
 * as an int (0/1/2 mapping the same way as the historical
 * diagnose_run() return value).
 */
int diag_run(unsigned domains);

/*
 * Per-domain registration entry points.  Each one registers its
 * domain's static const check entries with the registry, and is safe
 * to call multiple times.
 */
void diag_init_tls(void);
void diag_init_krb5(void);

/*
 * diagnose_run -- backward-compatible entry point.
 *
 * Equivalent to: diag_init_tls(); diag_run(DIAG_DOMAIN_TLS).
 *
 * Returns the same 0/1/2 verdict the historical implementation did.
 */
int diagnose_run(void);

/*
 * cert_info_run -- standalone certificate validation.
 *
 * Loads a certificate (and optionally a private key, CA, and required
 * SAN entries) and reports findings without performing any network IO.
 * Any of cert/key/ca may be NULL; the corresponding checks are skipped.
 *
 * Returns 0 if all attempted checks pass, 1 on any failure.
 */
int cert_info_run(const char *cert, const char *key, const char *ca,
                  const char *required_san);

#endif /* DIAGNOSE_H */
