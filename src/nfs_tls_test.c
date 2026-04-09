/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_tls_test.c -- RFC 9289 RPC-over-TLS stress tester.
 *
 * Repeatedly connects to an NFS server using STARTTLS (AUTH_TLS probe +
 * TLS handshake), optionally sends a post-handshake NULL RPC, and reports
 * connection latency statistics.
 *
 * Usage:
 *   nfs_tls_test --host SERVER [options]
 *
 * Options:
 *   --host HOST         NFS server hostname or IP (required)
 *   --port PORT         Port number (default: 2049)
 *   --iterations N      Number of STARTTLS connections (default: 10)
 *   --ca-cert FILE      CA certificate PEM for server verification
 *   --cert FILE         Client certificate PEM for mutual TLS
 *   --key FILE          Client private key PEM for mutual TLS
 *   --no-null           Skip post-handshake NULL RPC call
 *   --verbose           Print per-iteration result
 */

#include "tls_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <math.h>
#include <time.h>

/* --- timing helpers --- */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* --- statistics --- */

struct stats {
    double  s_min;
    double  s_max;
    double  s_sum;
    double  s_sum2;
    long    s_n;
    long    s_fail;
};

static void stats_init(struct stats *s)
{
    s->s_min  = 1e18;
    s->s_max  = -1e18;
    s->s_sum  = 0.0;
    s->s_sum2 = 0.0;
    s->s_n    = 0;
    s->s_fail = 0;
}

static void stats_add(struct stats *s, double v)
{
    if (v < s->s_min) s->s_min = v;
    if (v > s->s_max) s->s_max = v;
    s->s_sum  += v;
    s->s_sum2 += v * v;
    s->s_n++;
}

static void stats_print(const struct stats *s)
{
    if (s->s_n == 0) {
        printf("  (no successful iterations)\n");
        return;
    }
    double avg = s->s_sum / (double)s->s_n;
    double var = s->s_sum2 / (double)s->s_n - avg * avg;
    double sd  = (var > 0.0) ? sqrt(var) : 0.0;
    printf("  iterations : %ld ok, %ld fail\n", s->s_n, s->s_fail);
    printf("  latency ms : min=%.2f avg=%.2f max=%.2f stddev=%.2f\n",
           s->s_min * 1e3, avg * 1e3, s->s_max * 1e3, sd * 1e3);
}

/* --- option parsing --- */

struct options {
    const char *o_host;
    const char *o_port;
    long        o_iterations;
    const char *o_ca_cert;
    const char *o_cert;
    const char *o_key;
    int         o_no_null;
    int         o_verbose;
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --host HOST [options]\n"
            "\n"
            "Options:\n"
            "  --host HOST         NFS server hostname or IP (required)\n"
            "  --port PORT         Port number (default: 2049)\n"
            "  --iterations N      Number of connections (default: 10)\n"
            "  --ca-cert FILE      CA certificate PEM (skip verify if absent)\n"
            "  --cert FILE         Client certificate PEM (mutual TLS)\n"
            "  --key FILE          Client private key PEM (mutual TLS)\n"
            "  --no-null           Skip post-handshake NULL RPC\n"
            "  --verbose           Print per-iteration result\n"
            "\n"
            "Tests RFC 9289 RPC-over-TLS (STARTTLS): AUTH_TLS probe, TLS handshake,\n"
            "ALPN 'sunrpc' verification, optional NFS NULL call over TLS.\n",
            prog);
    exit(EXIT_FAILURE);
}

static void parse_options(int argc, char **argv, struct options *o)
{
    static const struct option long_opts[] = {
        { "host",       required_argument, NULL, 'H' },
        { "port",       required_argument, NULL, 'p' },
        { "iterations", required_argument, NULL, 'i' },
        { "ca-cert",    required_argument, NULL, 'C' },
        { "cert",       required_argument, NULL, 'c' },
        { "key",        required_argument, NULL, 'k' },
        { "no-null",    no_argument,       NULL, 'n' },
        { "verbose",    no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 }
    };

    memset(o, 0, sizeof(*o));
    o->o_port       = "2049";
    o->o_iterations = 10;

    int ch;
    while ((ch = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'H': o->o_host       = optarg;         break;
        case 'p': o->o_port       = optarg;         break;
        case 'i': o->o_iterations = atol(optarg);   break;
        case 'C': o->o_ca_cert    = optarg;         break;
        case 'c': o->o_cert       = optarg;         break;
        case 'k': o->o_key        = optarg;         break;
        case 'n': o->o_no_null    = 1;              break;
        case 'v': o->o_verbose    = 1;              break;
        default:
            usage(argv[0]);
        }
    }

    if (!o->o_host) {
        fprintf(stderr, "Error: --host is required\n\n");
        usage(argv[0]);
    }
    if (o->o_iterations <= 0) {
        fprintf(stderr, "Error: --iterations must be > 0\n\n");
        usage(argv[0]);
    }
    if ((o->o_cert && !o->o_key) || (!o->o_cert && o->o_key)) {
        fprintf(stderr, "Error: --cert and --key must be specified together\n\n");
        usage(argv[0]);
    }
}

/* --- main --- */

int main(int argc, char **argv)
{
    struct options o;
    parse_options(argc, argv, &o);

    printf("nfs_tls_test: %s:%s, %ld iterations%s\n",
           o.o_host, o.o_port, o.o_iterations,
           o.o_no_null ? "" : " + NULL RPC");

    SSL_CTX *ctx = tls_ctx_create(o.o_ca_cert, o.o_cert, o.o_key);
    if (!ctx) {
        fprintf(stderr, "Failed to create TLS context\n");
        return EXIT_FAILURE;
    }

    struct stats s;
    stats_init(&s);
    char errbuf[256];

    for (long i = 0; i < o.o_iterations; i++) {
        struct tls_conn conn;
        double t0 = now_sec();

        int rc = tls_connect_starttls(o.o_host, o.o_port, ctx, &conn,
                                      errbuf, sizeof(errbuf));
        if (rc == 0 && !o.o_no_null) {
            rc = tls_send_nfs_null(&conn, errbuf, sizeof(errbuf));
        }

        double elapsed = now_sec() - t0;

        if (rc == 0) {
            stats_add(&s, elapsed);
            if (o.o_verbose)
                printf("  [%4ld] OK %.2f ms\n", i + 1, elapsed * 1e3);
            tls_conn_close(&conn);
        } else {
            s.s_fail++;
            if (o.o_verbose)
                printf("  [%4ld] FAIL: %s\n", i + 1, errbuf);
            else
                fprintf(stderr, "iteration %ld: %s\n", i + 1, errbuf);
            /* conn may be partially initialised; close defensively */
            tls_conn_close(&conn);
        }
    }

    printf("\nResults:\n");
    stats_print(&s);

    SSL_CTX_free(ctx);

    return (s.s_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
