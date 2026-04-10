/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tls_stat.h -- /proc/net/tls_stat snapshot helpers.
 *
 * The Linux kernel TLS subsystem exports per-namespace counters in
 * /proc/net/tls_stat (see Documentation/networking/tls.rst).  These
 * counters reveal kernel-side TLS health -- decryption errors, rekey
 * failures, no-pad violations, etc. -- that are invisible from
 * user-space TLS APIs.
 *
 * Use tls_stat_snapshot() before and after a test run, then
 * tls_stat_diff_print() to display the deltas.
 */

#ifndef TLS_STAT_H
#define TLS_STAT_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Counter set we care about.  Field names mirror the kernel's
 * /proc/net/tls_stat labels.  All values are uint64_t cumulative
 * counts since boot (or namespace creation).
 *
 * present is set false if /proc/net/tls_stat could not be read at
 * all (non-Linux, kTLS not built, file missing).
 */
struct tls_stat {
    bool     present;
    uint64_t curr_tx_sw;
    uint64_t curr_rx_sw;
    uint64_t curr_tx_device;
    uint64_t curr_rx_device;
    uint64_t tx_sw;
    uint64_t rx_sw;
    uint64_t tx_device;
    uint64_t rx_device;
    uint64_t decrypt_error;
    uint64_t rx_no_pad_violation;
    uint64_t decrypt_retry;
    uint64_t tx_rekey_ok;
    uint64_t rx_rekey_ok;
    uint64_t tx_rekey_error;
    uint64_t rx_rekey_error;
    uint64_t rx_rekey_received;
};

/*
 * tls_stat_snapshot -- read /proc/net/tls_stat into out.
 * On any failure, out->present is set to false; the function still
 * returns 0 so callers can run unconditionally.
 */
int tls_stat_snapshot(struct tls_stat *out);

/*
 * tls_stat_diff_print -- print before/after deltas as a labelled
 * table.  Skips counters that did not change.  Highlights any
 * non-zero error counters with a '!' prefix.
 *
 * If either snapshot has present=false, prints a single explanatory
 * line and returns 0.  Returns the number of error counters that
 * incremented (callers can use this to upgrade verdicts to FAIL).
 */
int tls_stat_diff_print(const struct tls_stat *before,
                        const struct tls_stat *after);

#endif /* TLS_STAT_H */
