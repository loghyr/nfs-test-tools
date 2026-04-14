/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * stats.h -- header-only sample collection, percentile computation,
 * and ASCII histogram for the nfs_tls_test stress tester.
 *
 * All functions are static so this header can be included in a single
 * translation unit without link-time conflicts.
 */

#ifndef STATS_H
#define STATS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* --- sample storage --- */

/*
 * struct sample -- one complete connect-handshake-RPC measurement.
 *
 * s_rpc_ms is the mean latency across calls_per_conn RPCs; 0 when --no-null.
 * s_resumed is 1 if the TLS session was resumed from a prior iteration.
 */
struct sample {
	double s_total_ms;
	double s_tcp_ms;
	double s_probe_ms;
	double s_handshake_ms;
	double s_rpc_ms;
	int s_resumed;
};

/*
 * struct sample_array -- pre-allocated per-worker sample store.
 *
 * Avoids malloc in the hot path.  When full, sa_overflow is set and
 * further samples are dropped silently.
 */
struct sample_array {
	struct sample *sa_samples;
	size_t sa_cap;
	size_t sa_n;
	int sa_overflow;
};

/* Allocate storage for cap samples.  Returns 0 on success, -1 on ENOMEM. */
static int sa_init(struct sample_array *sa, size_t cap)
{
	sa->sa_samples = (struct sample *)malloc(cap * sizeof(struct sample));
	if (!sa->sa_samples)
		return -1;
	sa->sa_cap = cap;
	sa->sa_n = 0;
	sa->sa_overflow = 0;
	return 0;
}

/* Release storage.  Safe to call multiple times. */
static void sa_free(struct sample_array *sa)
{
	free(sa->sa_samples);
	sa->sa_samples = NULL;
	sa->sa_cap = 0;
	sa->sa_n = 0;
}

/* Add one sample; sets sa_overflow and drops the sample if the array is full. */
static void sa_add(struct sample_array *sa, const struct sample *s)
{
	if (sa->sa_n >= sa->sa_cap) {
		sa->sa_overflow = 1;
		return;
	}
	sa->sa_samples[sa->sa_n++] = *s;
}

/* --- percentile computation --- */

struct pct_result {
	double p50;
	double p95;
	double p99;
	double p999;
	double avg;
	double min;
	double max;
};

static int pct_cmp_double(const void *a, const void *b)
{
	double da = *(const double *)a;
	double db = *(const double *)b;
	return (da > db) - (da < db);
}

/*
 * pct_compute -- derive percentiles from a sorted double array.
 *
 * sorted must already be in ascending order (use qsort + pct_cmp_double).
 * sum is the pre-computed arithmetic sum of all values (for avg).
 */
static void pct_compute(const double *sorted, size_t n, double sum,
			struct pct_result *out)
{
	if (n == 0) {
		memset(out, 0, sizeof(*out));
		return;
	}
	out->min = sorted[0];
	out->max = sorted[n - 1];
	out->avg = sum / (double)n;
	out->p50 = sorted[(n * 50) / 100];
	out->p95 = sorted[(n * 95) / 100];
	out->p99 = sorted[(n * 99) / 100];
	out->p999 = sorted[(n * 999) / 1000];
}

/* --- ASCII histogram --- */

/*
 * Bucket boundaries (ms).  Defines 9 buckets:
 *   [0,1) [1,2) [2,4) [4,8) [8,16) [16,32) [32,64) [64,128) [128,inf)
 */
#define HISTO_NBOUNDS 8
#define HISTO_NBUCKETS 9

static const double histo_bounds[HISTO_NBOUNDS] = { 1.0,  2.0,	4.0,  8.0,
						    16.0, 32.0, 64.0, 128.0 };

static const char *const histo_labels[HISTO_NBUCKETS] = {
	"   0 -    1", "   1 -    2", "   2 -    4",
	"   4 -    8", "   8 -   16", "  16 -   32",
	"  32 -   64", "  64 -  128", " 128+      ",
};

/*
 * histogram_print -- render an ASCII bar chart of latency distribution.
 *
 * sorted must be in ascending order.  bar_width is the maximum bar length
 * in '#' characters (scales all bars relative to the tallest bucket).
 */
static void histogram_print(const double *sorted, size_t n, const char *label,
			    int bar_width)
{
	long counts[HISTO_NBUCKETS];
	memset(counts, 0, sizeof(counts));

	for (size_t i = 0; i < n; i++) {
		double v = sorted[i];
		int b = HISTO_NBUCKETS - 1; /* default: last bucket */
		for (int j = 0; j < HISTO_NBOUNDS; j++) {
			if (v < histo_bounds[j]) {
				b = j;
				break;
			}
		}
		counts[b]++;
	}

	long peak = 0;
	for (int b = 0; b < HISTO_NBUCKETS; b++)
		if (counts[b] > peak)
			peak = counts[b];

	printf("  Latency histogram (%s, ms):\n", label);
	for (int b = 0; b < HISTO_NBUCKETS; b++) {
		if (counts[b] == 0)
			continue;
		int bars = (peak > 0) ?
				   (int)((long)bar_width * counts[b] / peak) :
				   0;
		if (bars == 0 && counts[b] > 0)
			bars = 1;
		printf("  %s |", histo_labels[b]);
		for (int k = 0; k < bars; k++)
			putchar('#');
		printf("  %ld\n", counts[b]);
	}
}

#endif /* STATS_H */
