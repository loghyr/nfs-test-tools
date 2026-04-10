/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * diagnose.h -- local pre-flight checks for NFS-over-TLS readiness.
 *
 * Encodes the "Pre-flight checks" section of TROUBLESHOOTING.md as a
 * runnable check list.  Use --diagnose to run before the network test;
 * if any check fails, the network test won't work either.
 */

#ifndef DIAGNOSE_H
#define DIAGNOSE_H

/*
 * diagnose_run -- run all pre-flight checks and print a structured
 * PASS/FAIL/WARN report to stdout.
 *
 * Returns:
 *   0 if all checks PASS
 *   1 if any check FAILs
 *   2 if any check WARNs (and none failed)
 *
 * The output format is parseable by scripts/analyze_nfs_results.py
 * via lines of the form:
 *   DIAG: <check>: PASS|FAIL|WARN: <detail>
 */
int diagnose_run(void);

/*
 * cert_info_run -- standalone certificate validation.
 *
 * Loads a certificate (and optionally a private key, CA, and required
 * SAN entries) and reports findings without performing any network IO.
 * This is the openssl-equivalent of the certificate troubleshooting
 * commands in TROUBLESHOOTING.md, packaged as one tool invocation.
 *
 * Any of cert/key/ca may be NULL; the corresponding checks are skipped.
 * required_san may be NULL.
 *
 * Returns 0 if all attempted checks pass, 1 on any failure.
 */
int cert_info_run(const char *cert, const char *key, const char *ca,
                  const char *required_san);

#endif /* DIAGNOSE_H */
