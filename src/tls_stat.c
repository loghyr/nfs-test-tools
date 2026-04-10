/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tls_stat.c -- /proc/net/tls_stat snapshot helpers.
 *
 * /proc/net/tls_stat format is one line per counter:
 *   TlsCurrTxSw                     5
 *   TlsCurrRxSw                     5
 *   ...
 * with whitespace separation.
 */

#include "tls_stat.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define TLS_STAT_PATH "/proc/net/tls_stat"

/*
 * Field table mapping kernel counter names to struct offsets.
 */
struct field {
    const char *name;
    size_t      offset;
};

#define F(n, m) { n, offsetof(struct tls_stat, m) }

static const struct field s_fields[] = {
    F("TlsCurrTxSw",         curr_tx_sw),
    F("TlsCurrRxSw",         curr_rx_sw),
    F("TlsCurrTxDevice",     curr_tx_device),
    F("TlsCurrRxDevice",     curr_rx_device),
    F("TlsTxSw",             tx_sw),
    F("TlsRxSw",             rx_sw),
    F("TlsTxDevice",         tx_device),
    F("TlsRxDevice",         rx_device),
    F("TlsDecryptError",     decrypt_error),
    F("TlsRxNoPadViolation", rx_no_pad_violation),
    F("TlsDecryptRetry",     decrypt_retry),
    F("TlsTxRekeyOk",        tx_rekey_ok),
    F("TlsRxRekeyOk",        rx_rekey_ok),
    F("TlsTxRekeyError",     tx_rekey_error),
    F("TlsRxRekeyError",     rx_rekey_error),
    F("TlsRxRekeyReceived",  rx_rekey_received),
};

#define N_FIELDS (sizeof(s_fields) / sizeof(s_fields[0]))

/*
 * Set a uint64_t field by struct offset.
 */
static void set_field(struct tls_stat *s, size_t offset, uint64_t value)
{
    *(uint64_t *)((char *)s + offset) = value;
}

static uint64_t get_field(const struct tls_stat *s, size_t offset)
{
    return *(const uint64_t *)((const char *)s + offset);
}

int tls_stat_snapshot(struct tls_stat *out)
{
    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(TLS_STAT_PATH, "re");
    if (!fp) {
        out->present = false;
        return 0;  /* not an error -- just unsupported */
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char name[64];
        uint64_t value = 0;
        if (sscanf(line, "%63s %" SCNu64, name, &value) != 2)
            continue;
        for (size_t i = 0; i < N_FIELDS; i++) {
            if (strcmp(name, s_fields[i].name) == 0) {
                set_field(out, s_fields[i].offset, value);
                break;
            }
        }
    }
    fclose(fp);
    out->present = true;
    return 0;
}

/*
 * Counters that are *current* (gauge-style) rather than cumulative.
 * For these we want to print the absolute "after" value, not a delta.
 */
static int is_current(const char *name)
{
    return strstr(name, "Curr") != NULL;
}

/*
 * Counters that count error events.  Non-zero deltas in these are
 * worth flagging.
 */
static int is_error(const char *name)
{
    return strstr(name, "Error") != NULL ||
           strstr(name, "Violation") != NULL ||
           strstr(name, "Retry") != NULL;
}

int tls_stat_diff_print(const struct tls_stat *before,
                        const struct tls_stat *after)
{
    if (!before->present || !after->present) {
        printf("kTLS counters: %s not available\n", TLS_STAT_PATH);
        return 0;
    }

    int errors_seen = 0;
    int any_change = 0;

    printf("\nkTLS counters (%s):\n", TLS_STAT_PATH);

    for (size_t i = 0; i < N_FIELDS; i++) {
        uint64_t b = get_field(before, s_fields[i].offset);
        uint64_t a = get_field(after,  s_fields[i].offset);

        if (is_current(s_fields[i].name)) {
            /* Always show current gauges */
            printf("  %-24s %" PRIu64 "\n", s_fields[i].name, a);
            any_change = 1;
            continue;
        }

        if (a == b)
            continue;

        any_change = 1;
        uint64_t delta = a - b;
        const char *prefix = "  ";
        if (is_error(s_fields[i].name) && delta > 0) {
            errors_seen++;
            prefix = " !";
        }
        printf("%s%-24s +%" PRIu64 "\n", prefix, s_fields[i].name, delta);
    }

    if (!any_change)
        printf("  (no changes)\n");

    return errors_seen;
}
