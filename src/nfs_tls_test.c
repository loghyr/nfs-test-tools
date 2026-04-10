/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_tls_test.c -- RFC 9289 RPC-over-TLS stress tester.
 *
 * Drives N concurrent threads hammering a server with STARTTLS connections
 * and optional NULL RPCs, collecting per-phase latency samples and reporting
 * tail-latency percentiles (p50/p95/p99/p99.9) at the end of the run.
 *
 * Usage:
 *   nfs_tls_test --host SERVER [options]
 *
 * Options (inherited from v1):
 *   --host HOST         NFS server hostname or IP (required)
 *   --port PORT         Port number (default: 2049)
 *   --iterations N      Number of STARTTLS connections (default: 10)
 *   --ca-cert FILE      CA certificate PEM for server verification
 *   --cert FILE         Client certificate PEM for mutual TLS
 *   --key FILE          Client private key PEM for mutual TLS
 *   --no-null           Skip post-handshake NULL RPC call
 *   --verbose           Print per-connection result (threads=1 only)
 *
 * Stress options (v2):
 *   --threads N         Concurrent worker threads (default: 1)
 *   --duration N        Run for N seconds; overrides --iterations
 *   --calls-per-conn N  NULL RPCs per TLS connection (default: 1)
 *   --no-session-reuse  Force full TLS handshake each time
 *   --rate N            Target conn/s across all threads (default: unlimited)
 *   --progress N        Progress report interval in seconds (default: 10; 0=off)
 *   --tls-info          Print negotiated TLS version/cipher after first connect
 *   --histogram         Print ASCII latency histogram in final report
 */

#include "tls_client.h"
#include "stats.h"
#include "tls_stat.h"
#include "diagnose.h"
#include "tls_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <openssl/ssl.h>

/* --- global stop flags --- */

static _Atomic int g_stop         = 0;  /* set by main: duration expired */
static _Atomic int g_progress_stop = 0;  /* set by main: workers finished */
static _Atomic int g_tls_info_printed = 0;  /* set by first successful worker */

/* --- options --- */

struct options {
    const char *o_host;
    const char *o_port;
    long        o_iterations;     /* iterations per thread; LONG_MAX = unlimited */
    long        o_duration;       /* seconds, 0 = off */
    int         o_threads;
    int         o_calls_per_conn;
    int         o_no_session_reuse;
    long        o_rate;           /* target conn/s total, 0 = unlimited */
    int         o_progress;       /* interval seconds, 0 = off */
    int         o_tls_info;
    int         o_histogram;
    int         o_no_null;
    int         o_verbose;
    const char *o_ca_cert;
    const char *o_cert;
    const char *o_key;
    /* New in v3 */
    const char *o_keylog;          /* path to NSS keylog file, or NULL */
    const char *o_check_san;       /* required SAN list, or NULL */
    int         o_snapshot_stats;  /* 1 = read /proc/net/tls_stat before/after */
    int         o_diagnose;        /* 1 = run diagnose_run() and exit */
    int         o_require_tls13;   /* 1 = treat TLS 1.2 as FAIL not WARN */
    const char *o_require_alpn;    /* required ALPN protocol, or NULL */
    int         o_json;            /* 1 = emit JSON-only report on stdout */
    int         o_print_error_table; /* 1 = dump error taxonomy and exit */
};

/* --- per-worker state --- */

struct worker {
    pthread_t       w_thread;
    struct options *w_opts;
    SSL_CTX        *w_ctx;
    int             w_id;

    struct sample_array w_sa;         /* pre-allocated sample store */

    _Atomic long    w_attempts;
    _Atomic long    w_ok;
    _Atomic long    w_fail_tcp;
    _Atomic long    w_fail_probe;
    _Atomic long    w_fail_handshake;
    _Atomic long    w_fail_rpc;

    /* rate limiter: absolute CLOCK_MONOTONIC deadline for next connection */
    double          w_next_conn_time;
    /* XID base: w_id * 0x100000u; incremented by worker per call */
    uint32_t        w_xid;
    /* TLS session for resumption (NULL = no session or reuse disabled) */
    SSL_SESSION    *w_session;
};

/* --- timing helpers --- */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Sleep until absolute CLOCK_MONOTONIC time target_sec */
static void sleep_until(double target_sec)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)target_sec;
    ts.tv_nsec = (long)((target_sec - (double)ts.tv_sec) * 1e9);
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
}

/* --- worker thread --- */

static void *worker_thread(void *arg)
{
    struct worker  *w = (struct worker *)arg;
    struct options *o = w->w_opts;
    long            iter = 0;
    long            iter_limit = o->o_iterations;
    int             calls = o->o_no_null ? 0 : o->o_calls_per_conn;
    char            errbuf[256];

    /* Initialise rate limiter deadline to now */
    if (o->o_rate > 0)
        w->w_next_conn_time = now_sec();

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed) &&
           iter < iter_limit) {

        /* Rate limiting: sleep until our per-thread slot opens */
        if (o->o_rate > 0) {
            double now = now_sec();
            if (now < w->w_next_conn_time)
                sleep_until(w->w_next_conn_time);
            /* Advance window by per-thread interval = threads/rate */
            w->w_next_conn_time += (double)o->o_threads / (double)o->o_rate;
        }

        atomic_fetch_add_explicit(&w->w_attempts, 1, memory_order_relaxed);

        struct tls_conn  conn;
        struct tls_timing timing;
        uint32_t         xid = w->w_xid++;
        double           t0  = now_ms();

        /* --- TCP connect + AUTH_TLS probe + TLS handshake --- */
        int rc = tls_connect_starttls(o->o_host, o->o_port, w->w_ctx,
                                      o->o_no_session_reuse ? NULL : w->w_session,
                                      &conn, xid, &timing,
                                      errbuf, sizeof(errbuf));
        if (rc < 0) {
            /*
             * Classify the failure phase from the error message prefix so we
             * can report where connections are dying without parsing internals.
             * The prefix convention used by tls_client.c:
             *   "connect("    -> TCP
             *   "getaddrinfo" -> TCP
             *   "STARTTLS"    -> probe
             *   "SSL_connect" -> handshake
             *   "TLS ALPN"    -> handshake
             */
            if (strncmp(errbuf, "connect(", 8) == 0 ||
                strncmp(errbuf, "getaddrinfo", 11) == 0 ||
                strncmp(errbuf, "write AUTH", 10) == 0 ||
                strncmp(errbuf, "read record marker", 18) == 0) {
                atomic_fetch_add_explicit(&w->w_fail_tcp, 1,
                                          memory_order_relaxed);
            } else if (strncmp(errbuf, "STARTTLS", 8) == 0 ||
                       strncmp(errbuf, "read STARTTLS", 13) == 0) {
                atomic_fetch_add_explicit(&w->w_fail_probe, 1,
                                          memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&w->w_fail_handshake, 1,
                                          memory_order_relaxed);
            }
            if (o->o_verbose && o->o_threads == 1)
                printf("  [%4ld] FAIL: %s\n", iter + 1, errbuf);
            else
                fprintf(stderr, "worker %d iter %ld: %s\n",
                        w->w_id, iter + 1, errbuf);
            iter++;
            continue;
        }

        /* Print TLS info once, from whichever worker gets here first */
        if (o->o_tls_info) {
            int expected = 0;
            if (atomic_compare_exchange_strong_explicit(
                    &g_tls_info_printed, &expected, 1,
                    memory_order_acq_rel, memory_order_relaxed)) {
                tls_conn_print_info(&conn);
                char alpn[64];
                if (tls_conn_get_alpn(&conn, alpn, sizeof(alpn)) > 0)
                    printf("ALPN: %s\n", alpn);
            }
        }

        /* Optional --check-san: verify peer cert SAN contains the
         * required entries.  Counted as a handshake-phase failure. */
        if (o->o_check_san) {
            if (tls_conn_check_san(&conn, o->o_check_san,
                                   errbuf, sizeof(errbuf)) < 0) {
                atomic_fetch_add_explicit(&w->w_fail_handshake, 1,
                                          memory_order_relaxed);
                if (o->o_verbose && o->o_threads == 1)
                    printf("  [%4ld] SAN FAIL: %s\n", iter + 1, errbuf);
                else
                    fprintf(stderr, "worker %d iter %ld: %s\n",
                            w->w_id, iter + 1, errbuf);
                tls_conn_close(&conn);
                iter++;
                continue;
            }
        }

        /* Optional --require-tls13: anything below TLS 1.3 is a hard fail */
        if (o->o_require_tls13) {
            const char *ver = tls_conn_get_version(&conn);
            if (strcmp(ver, "TLSv1.3") != 0) {
                snprintf(errbuf, sizeof(errbuf),
                         "TLS version %s below required TLSv1.3", ver);
                atomic_fetch_add_explicit(&w->w_fail_handshake, 1,
                                          memory_order_relaxed);
                if (o->o_verbose && o->o_threads == 1)
                    printf("  [%4ld] TLS-VERSION FAIL: %s\n",
                           iter + 1, errbuf);
                tls_conn_close(&conn);
                iter++;
                continue;
            }
        }

        /* Optional --require-alpn: enforce a specific ALPN protocol */
        if (o->o_require_alpn) {
            char alpn[64];
            tls_conn_get_alpn(&conn, alpn, sizeof(alpn));
            if (strcmp(alpn, o->o_require_alpn) != 0) {
                snprintf(errbuf, sizeof(errbuf),
                         "ALPN '%s' does not match required '%s'",
                         alpn, o->o_require_alpn);
                atomic_fetch_add_explicit(&w->w_fail_handshake, 1,
                                          memory_order_relaxed);
                if (o->o_verbose && o->o_threads == 1)
                    printf("  [%4ld] ALPN FAIL: %s\n", iter + 1, errbuf);
                tls_conn_close(&conn);
                iter++;
                continue;
            }
        }

        /* Check if session was resumed before we swap it out */
        int resumed = SSL_session_reused(conn.tc_ssl);

        /* Update per-worker session for next iteration */
        SSL_SESSION_free(w->w_session);
        w->w_session = o->o_no_session_reuse ? NULL
                                             : tls_conn_get_session(&conn);

        /* --- post-handshake NULL RPCs --- */
        double rpc_sum = 0.0;
        int    rpc_ok  = 1;
        for (int c = 0; c < calls && rpc_ok; c++) {
            uint32_t rxid = w->w_xid++;
            double   r0   = now_ms();
            int      rrc  = tls_send_nfs_null(&conn, rxid, errbuf, sizeof(errbuf));
            double   r1   = now_ms();
            if (rrc < 0) {
                rpc_ok = 0;
                atomic_fetch_add_explicit(&w->w_fail_rpc, 1,
                                          memory_order_relaxed);
                if (o->o_verbose && o->o_threads == 1)
                    printf("  [%4ld] RPC FAIL: %s\n", iter + 1, errbuf);
            } else {
                rpc_sum += r1 - r0;
            }
        }

        double total_ms = now_ms() - t0;

        tls_conn_close(&conn);

        if (rpc_ok) {
            struct sample s;
            s.s_total_ms     = total_ms;
            s.s_tcp_ms       = timing.tt_tcp_ms;
            s.s_probe_ms     = timing.tt_probe_ms;
            s.s_handshake_ms = timing.tt_handshake_ms;
            s.s_rpc_ms       = (calls > 0) ? (rpc_sum / calls) : 0.0;
            s.s_resumed      = resumed;
            sa_add(&w->w_sa, &s);
            atomic_fetch_add_explicit(&w->w_ok, 1, memory_order_relaxed);

            if (o->o_verbose && o->o_threads == 1)
                printf("  [%4ld] OK %.2f ms\n", iter + 1, total_ms);
        }

        iter++;
    }

    return NULL;
}

/* --- progress thread --- */

struct progress_state {
    struct worker  *workers;
    int             nworkers;
    int             interval_sec;
    double          start_sec;
};

static void *progress_thread(void *arg)
{
    struct progress_state *ps = (struct progress_state *)arg;
    double last_ok = 0.0;
    double last_ts = now_sec();

    while (!atomic_load_explicit(&g_progress_stop, memory_order_relaxed)) {
        struct timespec ts;
        ts.tv_sec  = ps->interval_sec;
        ts.tv_nsec = 0;
        /* nanosleep relative; wake up early if signalled is fine */
        nanosleep(&ts, NULL);

        if (atomic_load_explicit(&g_progress_stop, memory_order_relaxed))
            break;

        double now    = now_sec();
        double elap   = now - ps->start_sec;
        double window = now - last_ts;

        long total_att = 0, total_ok = 0, total_fail = 0;
        for (int i = 0; i < ps->nworkers; i++) {
            total_att  += atomic_load_explicit(&ps->workers[i].w_attempts,
                                               memory_order_relaxed);
            total_ok   += atomic_load_explicit(&ps->workers[i].w_ok,
                                               memory_order_relaxed);
            long ftcp  = atomic_load_explicit(&ps->workers[i].w_fail_tcp,
                                              memory_order_relaxed);
            long fprb  = atomic_load_explicit(&ps->workers[i].w_fail_probe,
                                              memory_order_relaxed);
            long fhs   = atomic_load_explicit(&ps->workers[i].w_fail_handshake,
                                              memory_order_relaxed);
            long frpc  = atomic_load_explicit(&ps->workers[i].w_fail_rpc,
                                              memory_order_relaxed);
            total_fail += ftcp + fprb + fhs + frpc;
        }

        double delta_ok = (double)total_ok - last_ok;
        double rate     = (window > 0.0) ? delta_ok / window : 0.0;
        last_ok         = (double)total_ok;
        last_ts         = now;

        printf("[%4.0fs] %ld attempts, %ld ok (%ld fail), %.1f conn/s\n",
               elap, total_att, total_ok, total_fail, rate);
        fflush(stdout);
    }
    return NULL;
}

/* --- option parsing --- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --host HOST [options]\n"
        "       %s --diagnose\n"
        "\n"
        "Connection options:\n"
        "  --host HOST           NFS server hostname or IP\n"
        "  --port PORT           Port number (default: 2049)\n"
        "  --iterations N        Number of connections per thread (default: 10)\n"
        "  --ca-cert FILE        CA certificate PEM (skip verify if absent)\n"
        "  --cert FILE           Client certificate PEM (mutual TLS)\n"
        "  --key FILE            Client private key PEM (mutual TLS)\n"
        "  --no-null             Skip post-handshake NULL RPC\n"
        "  --verbose             Print per-connection result (single-thread only)\n"
        "\n"
        "Stress options:\n"
        "  --threads N           Concurrent worker threads (default: 1)\n"
        "  --duration N          Run for N seconds (overrides --iterations)\n"
        "  --calls-per-conn N    NULL RPCs per TLS connection (default: 1)\n"
        "  --no-session-reuse    Force full TLS handshake each time\n"
        "  --rate N              Target conn/s total (default: unlimited)\n"
        "  --progress N          Progress interval seconds (default: 10; 0=off)\n"
        "\n"
        "Reporting:\n"
        "  --tls-info            Print negotiated TLS version/cipher/ALPN\n"
        "  --histogram           Print ASCII latency histogram\n"
        "  --snapshot-stats      Read /proc/net/tls_stat before/after run\n"
        "  --output text|json    Report format (default: text)\n"
        "\n"
        "Diagnostic and strict-mode options:\n"
        "  --diagnose            Run local pre-flight checks and exit\n"
        "  --print-error-table   Print the canonical error taxonomy and exit\n"
        "  --keylog FILE         Write NSS-format TLS key log for Wireshark\n"
        "  --check-san LIST      Verify server cert SAN includes these entries\n"
        "                        (comma-separated 'IP:...,DNS:...')\n"
        "  --require-tls13       Treat anything below TLS 1.3 as a failure\n"
        "  --require-alpn NAME   Require this ALPN protocol (default: 'sunrpc')\n"
        "\n"
        "Tests RFC 9289 RPC-over-TLS (STARTTLS): AUTH_TLS probe, TLS handshake,\n"
        "ALPN 'sunrpc' verification, optional NFS NULL call over TLS.\n",
        prog, prog);
    exit(EXIT_FAILURE);
}

static void parse_options(int argc, char **argv, struct options *o)
{
    static const struct option long_opts[] = {
        { "host",             required_argument, NULL, 'H' },
        { "port",             required_argument, NULL, 'p' },
        { "iterations",       required_argument, NULL, 'i' },
        { "ca-cert",          required_argument, NULL, 'C' },
        { "cert",             required_argument, NULL, 'c' },
        { "key",              required_argument, NULL, 'k' },
        { "no-null",          no_argument,       NULL, 'n' },
        { "verbose",          no_argument,       NULL, 'v' },
        { "threads",          required_argument, NULL, 't' },
        { "duration",         required_argument, NULL, 'd' },
        { "calls-per-conn",   required_argument, NULL, 'K' },
        { "no-session-reuse", no_argument,       NULL, 'R' },
        { "rate",             required_argument, NULL, 'r' },
        { "progress",         required_argument, NULL, 'P' },
        { "tls-info",         no_argument,       NULL, 'I' },
        { "histogram",        no_argument,       NULL, 'A' },
        { "keylog",           required_argument, NULL, 'L' },
        { "check-san",        required_argument, NULL, 'S' },
        { "snapshot-stats",   no_argument,       NULL, 'T' },
        { "diagnose",         no_argument,       NULL, 'D' },
        { "require-tls13",    no_argument,       NULL, '3' },
        { "require-alpn",     required_argument, NULL, 'N' },
        { "output",           required_argument, NULL, 'O' },
        { "print-error-table",no_argument,       NULL, 'E' },
        { NULL, 0, NULL, 0 }
    };

    memset(o, 0, sizeof(*o));
    o->o_port          = "2049";
    o->o_iterations    = 10;
    o->o_threads       = 1;
    o->o_calls_per_conn = 1;
    o->o_progress      = 10;

    int ch;
    while ((ch = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'H': o->o_host           = optarg;         break;
        case 'p': o->o_port           = optarg;         break;
        case 'i': o->o_iterations     = atol(optarg);   break;
        case 'C': o->o_ca_cert        = optarg;         break;
        case 'c': o->o_cert           = optarg;         break;
        case 'k': o->o_key            = optarg;         break;
        case 'n': o->o_no_null        = 1;              break;
        case 'v': o->o_verbose        = 1;              break;
        case 't': o->o_threads        = atoi(optarg);   break;
        case 'd': o->o_duration       = atol(optarg);   break;
        case 'K': o->o_calls_per_conn = atoi(optarg);   break;
        case 'R': o->o_no_session_reuse = 1;            break;
        case 'r': o->o_rate           = atol(optarg);   break;
        case 'P': o->o_progress       = atoi(optarg);   break;
        case 'I': o->o_tls_info       = 1;              break;
        case 'A': o->o_histogram      = 1;              break;
        case 'L': o->o_keylog         = optarg;         break;
        case 'S': o->o_check_san      = optarg;         break;
        case 'T': o->o_snapshot_stats = 1;              break;
        case 'D': o->o_diagnose       = 1;              break;
        case '3': o->o_require_tls13  = 1;              break;
        case 'N': o->o_require_alpn   = optarg;         break;
        case 'O':
            if (strcmp(optarg, "json") == 0)
                o->o_json = 1;
            else if (strcmp(optarg, "text") == 0)
                o->o_json = 0;
            else {
                fprintf(stderr, "Error: --output must be 'text' or 'json'\n\n");
                usage(argv[0]);
            }
            break;
        case 'E': o->o_print_error_table = 1; break;
        default:
            usage(argv[0]);
        }
    }

    /* --diagnose and --print-error-table run without a host */
    if (o->o_diagnose || o->o_print_error_table)
        return;

    if (!o->o_host) {
        fprintf(stderr, "Error: --host is required\n\n");
        usage(argv[0]);
    }
    if (o->o_iterations <= 0 && o->o_duration <= 0) {
        fprintf(stderr, "Error: --iterations must be > 0\n\n");
        usage(argv[0]);
    }
    if (o->o_threads <= 0 || o->o_threads > 256) {
        fprintf(stderr, "Error: --threads must be 1..256\n\n");
        usage(argv[0]);
    }
    if (o->o_calls_per_conn <= 0) {
        fprintf(stderr, "Error: --calls-per-conn must be > 0\n\n");
        usage(argv[0]);
    }
    if ((o->o_cert && !o->o_key) || (!o->o_cert && o->o_key)) {
        fprintf(stderr, "Error: --cert and --key must be specified together\n\n");
        usage(argv[0]);
    }
    /* Duration overrides iterations */
    if (o->o_duration > 0)
        o->o_iterations = (long)2e9;  /* effectively unlimited */
}

/* --- report --- */

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void print_pct_row(const char *label, const struct pct_result *r)
{
    printf("  %-10s%7.2f %7.2f %7.2f %8.2f %7.2f %7.2f %7.2f\n",
           label,
           r->p50, r->p95, r->p99, r->p999, r->avg, r->min, r->max);
}

static void print_report(const struct options *o,
                         struct worker *workers, int nworkers,
                         double elapsed_ms)
{
    /* Count total successful samples */
    size_t total = 0;
    long   total_ok = 0, fail_tcp = 0, fail_probe = 0;
    long   fail_hs = 0, fail_rpc = 0, resumed = 0;
    int    any_overflow = 0;

    for (int i = 0; i < nworkers; i++) {
        total       += workers[i].w_sa.sa_n;
        total_ok    += atomic_load_explicit(&workers[i].w_ok,
                                            memory_order_relaxed);
        fail_tcp    += atomic_load_explicit(&workers[i].w_fail_tcp,
                                            memory_order_relaxed);
        fail_probe  += atomic_load_explicit(&workers[i].w_fail_probe,
                                            memory_order_relaxed);
        fail_hs     += atomic_load_explicit(&workers[i].w_fail_handshake,
                                            memory_order_relaxed);
        fail_rpc    += atomic_load_explicit(&workers[i].w_fail_rpc,
                                            memory_order_relaxed);
        if (workers[i].w_sa.sa_overflow)
            any_overflow = 1;
    }

    /* Merge per-worker samples into flat sorted arrays */
    double *ms_total = NULL, *ms_tcp = NULL, *ms_probe = NULL;
    double *ms_hs    = NULL, *ms_rpc = NULL;
    double  sum_total = 0.0, sum_tcp = 0.0, sum_probe = 0.0;
    double  sum_hs    = 0.0, sum_rpc = 0.0;

    int have_rpc = (!o->o_no_null && total > 0);

    if (total > 0) {
        ms_total = (double *)malloc(total * sizeof(double));
        ms_tcp   = (double *)malloc(total * sizeof(double));
        ms_probe = (double *)malloc(total * sizeof(double));
        ms_hs    = (double *)malloc(total * sizeof(double));
        if (have_rpc)
            ms_rpc = (double *)malloc(total * sizeof(double));

        if (!ms_total || !ms_tcp || !ms_probe || !ms_hs ||
            (have_rpc && !ms_rpc)) {
            fprintf(stderr, "report: out of memory\n");
            free(ms_total); free(ms_tcp); free(ms_probe);
            free(ms_hs); free(ms_rpc);
            return;
        }

        size_t pos = 0;
        for (int i = 0; i < nworkers; i++) {
            for (size_t j = 0; j < workers[i].w_sa.sa_n; j++) {
                const struct sample *s = &workers[i].w_sa.sa_samples[j];
                ms_total[pos] = s->s_total_ms;
                ms_tcp[pos]   = s->s_tcp_ms;
                ms_probe[pos] = s->s_probe_ms;
                ms_hs[pos]    = s->s_handshake_ms;
                if (have_rpc)
                    ms_rpc[pos] = s->s_rpc_ms;
                sum_total += s->s_total_ms;
                sum_tcp   += s->s_tcp_ms;
                sum_probe += s->s_probe_ms;
                sum_hs    += s->s_handshake_ms;
                if (have_rpc)
                    sum_rpc += s->s_rpc_ms;
                if (s->s_resumed)
                    resumed++;
                pos++;
            }
        }

        qsort(ms_total, total, sizeof(double), cmp_double);
        qsort(ms_tcp,   total, sizeof(double), cmp_double);
        qsort(ms_probe, total, sizeof(double), cmp_double);
        qsort(ms_hs,    total, sizeof(double), cmp_double);
        if (have_rpc)
            qsort(ms_rpc, total, sizeof(double), cmp_double);
    }

    /* Header */
    long full_hs  = total_ok - resumed;
    long total_fail = fail_tcp + fail_probe + fail_hs + fail_rpc;
    long total_att = total_ok + total_fail;

    printf("\nnfs_tls_test: %s:%s, %d thread%s",
           o->o_host, o->o_port, nworkers, nworkers > 1 ? "s" : "");
    if (o->o_duration > 0)
        printf(", %.1f s", elapsed_ms / 1e3);
    else
        printf(", %ld iterations", total_att);
    if (!o->o_no_null)
        printf(", %d call%s/conn",
               o->o_calls_per_conn, o->o_calls_per_conn > 1 ? "s" : "");
    printf("\n");

    if (any_overflow)
        printf("WARNING: sample buffer overflowed -- some samples dropped\n");

    if (o->o_tls_info && !atomic_load_explicit(&g_tls_info_printed,
                                                memory_order_relaxed))
        printf("TLS: (no successful connections)\n");

    printf("Sessions: %ld resumed, %ld full handshake\n", resumed, full_hs);
    printf("\nTotal connections: %ld ok, %ld fail\n", total_ok, total_fail);

    if (total > 0) {
        struct pct_result pr_total, pr_tcp, pr_probe, pr_hs, pr_rpc;
        pct_compute(ms_total, total, sum_total, &pr_total);
        pct_compute(ms_tcp,   total, sum_tcp,   &pr_tcp);
        pct_compute(ms_probe, total, sum_probe,  &pr_probe);
        pct_compute(ms_hs,    total, sum_hs,    &pr_hs);
        if (have_rpc)
            pct_compute(ms_rpc, total, sum_rpc, &pr_rpc);

        printf("  Phase breakdown (ms):\n");
        printf("  %-10s%7s %7s %7s %8s %7s %7s %7s\n",
               "", "p50", "p95", "p99", "p99.9", "avg", "min", "max");
        print_pct_row("tcp",       &pr_tcp);
        print_pct_row("probe",     &pr_probe);
        print_pct_row("handshake", &pr_hs);
        if (have_rpc)
            print_pct_row("rpc",   &pr_rpc);
        print_pct_row("total",     &pr_total);

        if (o->o_histogram)
            histogram_print(ms_total, total, "total", 40);
    }

    printf("\nError breakdown: %ld tcp, %ld probe, %ld handshake, %ld rpc\n",
           fail_tcp, fail_probe, fail_hs, fail_rpc);

    /*
     * For each phase that had failures, print one canonical error
     * descriptor with a pointer to the matching TROUBLESHOOTING.md
     * section.  Testers can copy the symbolic name into bug reports
     * and CI matchers without parsing the prose.
     */
    const struct {
        long             count;
        enum tls_phase   phase;
    } phase_summary[] = {
        { fail_tcp,    TLS_PHASE_TCP       },
        { fail_probe,  TLS_PHASE_PROBE     },
        { fail_hs,     TLS_PHASE_HANDSHAKE },
        { fail_rpc,    TLS_PHASE_RPC       },
    };
    int any_phase_failed = 0;
    for (size_t i = 0; i < sizeof(phase_summary)/sizeof(phase_summary[0]); i++) {
        if (phase_summary[i].count <= 0)
            continue;
        if (!any_phase_failed) {
            printf("\nMost likely causes (see TROUBLESHOOTING.md for details):\n");
            any_phase_failed = 1;
        }
        char ctx[64];
        snprintf(ctx, sizeof(ctx),
                 "%ld %s failure%s",
                 phase_summary[i].count,
                 tls_error_phase_name(phase_summary[i].phase),
                 phase_summary[i].count == 1 ? "" : "s");
        tls_error_emit_one(stdout,
                           tls_error_default_for_phase(phase_summary[i].phase),
                           ctx);
    }

    free(ms_total); free(ms_tcp); free(ms_probe); free(ms_hs); free(ms_rpc);
}

/*
 * print_report_json -- emit the same data as print_report() in JSON.
 *
 * The JSON has a stable shape suitable for CI tooling:
 *
 *   {
 *     "host": "...", "port": "...", "threads": N,
 *     "iterations": N, "duration_s": N,
 *     "ok": N, "fail": N,
 *     "fail_breakdown": {
 *       "tcp": N, "probe": N, "handshake": N, "rpc": N
 *     },
 *     "sessions": { "resumed": N, "full_handshake": N },
 *     "phases_ms": {
 *       "tcp":       { "p50": .., "p95": .., "p99": .., "p999": .., ... },
 *       "probe":     { ... },
 *       "handshake": { ... },
 *       "rpc":       { ... },        // omitted if --no-null
 *       "total":     { ... }
 *     }
 *   }
 *
 * No human-readable preamble: a JSON-only line is the entire stdout.
 */
static void print_pct_json(const char *name, const struct pct_result *r,
                           int last)
{
    printf("    \"%s\": { \"p50\": %.3f, \"p95\": %.3f, "
           "\"p99\": %.3f, \"p999\": %.3f, "
           "\"avg\": %.3f, \"min\": %.3f, \"max\": %.3f }%s\n",
           name, r->p50, r->p95, r->p99, r->p999,
           r->avg, r->min, r->max, last ? "" : ",");
}

static void print_report_json(const struct options *o,
                              struct worker *workers, int nworkers,
                              double elapsed_ms)
{
    size_t total = 0;
    long   total_ok = 0, fail_tcp = 0, fail_probe = 0;
    long   fail_hs = 0, fail_rpc = 0, resumed = 0;

    for (int i = 0; i < nworkers; i++) {
        total      += workers[i].w_sa.sa_n;
        total_ok   += atomic_load_explicit(&workers[i].w_ok,
                                           memory_order_relaxed);
        fail_tcp   += atomic_load_explicit(&workers[i].w_fail_tcp,
                                           memory_order_relaxed);
        fail_probe += atomic_load_explicit(&workers[i].w_fail_probe,
                                           memory_order_relaxed);
        fail_hs    += atomic_load_explicit(&workers[i].w_fail_handshake,
                                           memory_order_relaxed);
        fail_rpc   += atomic_load_explicit(&workers[i].w_fail_rpc,
                                           memory_order_relaxed);
    }

    double *ms_total = NULL, *ms_tcp = NULL, *ms_probe = NULL;
    double *ms_hs = NULL, *ms_rpc = NULL;
    double sum_total = 0.0, sum_tcp = 0.0, sum_probe = 0.0;
    double sum_hs = 0.0, sum_rpc = 0.0;
    int have_rpc = (!o->o_no_null && total > 0);

    if (total > 0) {
        ms_total = (double *)malloc(total * sizeof(double));
        ms_tcp   = (double *)malloc(total * sizeof(double));
        ms_probe = (double *)malloc(total * sizeof(double));
        ms_hs    = (double *)malloc(total * sizeof(double));
        if (have_rpc)
            ms_rpc = (double *)malloc(total * sizeof(double));

        if (!ms_total || !ms_tcp || !ms_probe || !ms_hs ||
            (have_rpc && !ms_rpc)) {
            free(ms_total); free(ms_tcp); free(ms_probe);
            free(ms_hs); free(ms_rpc);
            fprintf(stderr, "report_json: out of memory\n");
            return;
        }

        size_t pos = 0;
        for (int i = 0; i < nworkers; i++) {
            for (size_t j = 0; j < workers[i].w_sa.sa_n; j++) {
                const struct sample *s = &workers[i].w_sa.sa_samples[j];
                ms_total[pos] = s->s_total_ms;
                ms_tcp[pos]   = s->s_tcp_ms;
                ms_probe[pos] = s->s_probe_ms;
                ms_hs[pos]    = s->s_handshake_ms;
                if (have_rpc)
                    ms_rpc[pos] = s->s_rpc_ms;
                sum_total += s->s_total_ms;
                sum_tcp   += s->s_tcp_ms;
                sum_probe += s->s_probe_ms;
                sum_hs    += s->s_handshake_ms;
                if (have_rpc)
                    sum_rpc += s->s_rpc_ms;
                if (s->s_resumed)
                    resumed++;
                pos++;
            }
        }

        qsort(ms_total, total, sizeof(double), cmp_double);
        qsort(ms_tcp,   total, sizeof(double), cmp_double);
        qsort(ms_probe, total, sizeof(double), cmp_double);
        qsort(ms_hs,    total, sizeof(double), cmp_double);
        if (have_rpc)
            qsort(ms_rpc, total, sizeof(double), cmp_double);
    }

    long full_hs = total_ok - resumed;

    printf("{\n");
    printf("  \"host\": \"%s\",\n", o->o_host);
    printf("  \"port\": \"%s\",\n", o->o_port);
    printf("  \"threads\": %d,\n", nworkers);
    if (o->o_duration > 0)
        printf("  \"duration_s\": %.3f,\n", elapsed_ms / 1e3);
    printf("  \"ok\": %ld,\n", total_ok);
    printf("  \"fail\": %ld,\n", fail_tcp + fail_probe + fail_hs + fail_rpc);
    printf("  \"fail_breakdown\": { \"tcp\": %ld, \"probe\": %ld, "
           "\"handshake\": %ld, \"rpc\": %ld },\n",
           fail_tcp, fail_probe, fail_hs, fail_rpc);
    printf("  \"sessions\": { \"resumed\": %ld, \"full_handshake\": %ld },\n",
           resumed, full_hs);

    if (total > 0) {
        struct pct_result pr_total, pr_tcp, pr_probe, pr_hs, pr_rpc;
        pct_compute(ms_total, total, sum_total, &pr_total);
        pct_compute(ms_tcp,   total, sum_tcp,   &pr_tcp);
        pct_compute(ms_probe, total, sum_probe, &pr_probe);
        pct_compute(ms_hs,    total, sum_hs,    &pr_hs);
        if (have_rpc)
            pct_compute(ms_rpc, total, sum_rpc, &pr_rpc);

        printf("  \"phases_ms\": {\n");
        print_pct_json("tcp",       &pr_tcp,   0);
        print_pct_json("probe",     &pr_probe, 0);
        print_pct_json("handshake", &pr_hs,    have_rpc ? 0 : 1);
        if (have_rpc)
            print_pct_json("rpc",   &pr_rpc,   0);
        print_pct_json("total",     &pr_total, 1);
        printf("  }\n");
    } else {
        printf("  \"phases_ms\": {}\n");
    }

    printf("}\n");

    free(ms_total); free(ms_tcp); free(ms_probe); free(ms_hs); free(ms_rpc);
}

/* --- main --- */

int main(int argc, char **argv)
{
    struct options o;
    parse_options(argc, argv, &o);

    /* --diagnose: run pre-flight checks and exit before anything else */
    if (o.o_diagnose)
        return diagnose_run();

    /* --print-error-table: dump the canonical taxonomy and exit */
    if (o.o_print_error_table) {
        tls_error_print_table();
        return EXIT_SUCCESS;
    }

    SSL_CTX *ctx = tls_ctx_create(o.o_ca_cert, o.o_cert, o.o_key);
    if (!ctx) {
        fprintf(stderr, "Failed to create TLS context\n");
        return EXIT_FAILURE;
    }

    /* Optional NSS-format keylog for Wireshark decryption */
    if (o.o_keylog) {
        if (tls_ctx_enable_keylog(ctx, o.o_keylog) < 0) {
            SSL_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        printf("TLS keylog: writing session keys to %s\n", o.o_keylog);
    }

    /* Optional /proc/net/tls_stat snapshot before the test */
    struct tls_stat ts_before, ts_after;
    if (o.o_snapshot_stats)
        tls_stat_snapshot(&ts_before);

    int nworkers = o.o_threads;

    /* Per-worker sample capacity */
    size_t iter_per_worker;
    if (o.o_duration > 0) {
        /* Conservative: max 10000 conn/s for up to o_duration seconds */
        size_t max_rate = (o.o_rate > 0) ? (size_t)o.o_rate : 10000;
        iter_per_worker = (size_t)o.o_duration * max_rate / (size_t)nworkers
                          + 1024;
    } else {
        iter_per_worker = (size_t)((o.o_iterations + nworkers - 1) / nworkers);
    }

    struct worker *workers = (struct worker *)calloc(
        (size_t)nworkers, sizeof(struct worker));
    if (!workers) {
        fprintf(stderr, "Out of memory allocating workers\n");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < nworkers; i++) {
        workers[i].w_opts    = &o;
        workers[i].w_ctx     = ctx;
        workers[i].w_id      = i;
        workers[i].w_xid     = (uint32_t)i * 0x100000u;
        workers[i].w_session = NULL;
        if (sa_init(&workers[i].w_sa, iter_per_worker) < 0) {
            fprintf(stderr, "Out of memory allocating sample array "
                    "(worker %d, %zu samples)\n", i, iter_per_worker);
            for (int j = 0; j < i; j++)
                sa_free(&workers[j].w_sa);
            free(workers);
            SSL_CTX_free(ctx);
            return EXIT_FAILURE;
        }
    }

    /* Duration mode: record start time for clock_nanosleep */
    struct timespec duration_end;
    if (o.o_duration > 0) {
        clock_gettime(CLOCK_MONOTONIC, &duration_end);
        duration_end.tv_sec += o.o_duration;
    }

    double start_sec = now_sec();

    /* Spawn worker threads */
    for (int i = 0; i < nworkers; i++) {
        if (pthread_create(&workers[i].w_thread, NULL,
                           worker_thread, &workers[i]) != 0) {
            fprintf(stderr, "pthread_create worker %d failed\n", i);
            atomic_store_explicit(&g_stop, 1, memory_order_release);
            for (int j = 0; j < i; j++)
                pthread_join(workers[j].w_thread, NULL);
            for (int j = 0; j < nworkers; j++)
                sa_free(&workers[j].w_sa);
            free(workers);
            SSL_CTX_free(ctx);
            return EXIT_FAILURE;
        }
    }

    /* Spawn progress thread */
    pthread_t progress_tid = 0;
    struct progress_state ps = {
        .workers      = workers,
        .nworkers     = nworkers,
        .interval_sec = o.o_progress,
        .start_sec    = start_sec,
    };
    if (o.o_progress > 0) {
        if (pthread_create(&progress_tid, NULL, progress_thread, &ps) != 0) {
            fprintf(stderr, "pthread_create progress thread failed\n");
            progress_tid = 0;
        }
    }

    /* Wait for duration, then signal workers to stop */
    if (o.o_duration > 0) {
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &duration_end, NULL);
        atomic_store_explicit(&g_stop, 1, memory_order_release);
    }

    /* Join all worker threads */
    for (int i = 0; i < nworkers; i++)
        pthread_join(workers[i].w_thread, NULL);

    double elapsed_ms = now_ms() - start_sec * 1e3;

    /* Stop and join progress thread */
    if (progress_tid) {
        atomic_store_explicit(&g_progress_stop, 1, memory_order_release);
        pthread_join(progress_tid, NULL);
    }

    /* Snapshot kTLS counters after the run, before printing the report */
    if (o.o_snapshot_stats)
        tls_stat_snapshot(&ts_after);

    /* Print final report (text or JSON) */
    if (o.o_json)
        print_report_json(&o, workers, nworkers, elapsed_ms);
    else
        print_report(&o, workers, nworkers, elapsed_ms);

    /* Print kTLS counter deltas if requested.  Suppressed in JSON mode
     * since the deltas would break the single-object JSON contract;
     * the JSON consumer can read /proc/net/tls_stat itself if needed. */
    int ktls_errors = 0;
    if (o.o_snapshot_stats && !o.o_json)
        ktls_errors = tls_stat_diff_print(&ts_before, &ts_after);

    /*
     * Compute canonical exit status from per-phase failure counts.
     *
     * Reason: shell users / CI can match on the symbolic exit code to
     * decide what failed.  TLS_ERR_OK on success, the phase's default
     * code if exactly one phase failed, TLS_ERR_MIXED if more than one
     * class failed in the same run.
     *
     * This replaces the historical EXIT_FAILURE-on-any-failure
     * behaviour.  Codes live in the 10..99 range so they don't collide
     * with the standard 0/1/2 shell convention badly, and are stable
     * across releases per the tls_error.h taxonomy.
     */
    long fail_tcp_total = 0, fail_probe_total = 0;
    long fail_hs_total  = 0, fail_rpc_total   = 0;
    for (int i = 0; i < nworkers; i++) {
        fail_tcp_total   += atomic_load_explicit(&workers[i].w_fail_tcp,
                                                 memory_order_relaxed);
        fail_probe_total += atomic_load_explicit(&workers[i].w_fail_probe,
                                                 memory_order_relaxed);
        fail_hs_total    += atomic_load_explicit(&workers[i].w_fail_handshake,
                                                 memory_order_relaxed);
        fail_rpc_total   += atomic_load_explicit(&workers[i].w_fail_rpc,
                                                 memory_order_relaxed);
    }
    long total_fail = fail_tcp_total + fail_probe_total
                    + fail_hs_total  + fail_rpc_total;

    int distinct_classes = 0;
    enum tls_error_code single_code = TLS_ERR_OK;
    if (fail_tcp_total > 0) {
        distinct_classes++;
        single_code = TLS_ERR_TCP_REFUSED;
    }
    if (fail_probe_total > 0) {
        distinct_classes++;
        single_code = TLS_ERR_PROBE_REJECTED;
    }
    if (fail_hs_total > 0) {
        distinct_classes++;
        single_code = TLS_ERR_HANDSHAKE_FAILED;
    }
    if (fail_rpc_total > 0) {
        distinct_classes++;
        single_code = TLS_ERR_RPC_FAILED;
    }
    if (ktls_errors > 0) {
        distinct_classes++;
        single_code = TLS_ERR_KTLS_DECRYPT_ERROR;
    }

    enum tls_error_code exit_code;
    if (total_fail == 0 && ktls_errors == 0)
        exit_code = TLS_ERR_OK;
    else if (distinct_classes == 1)
        exit_code = single_code;
    else
        exit_code = TLS_ERR_MIXED;

    /* Cleanup */
    for (int i = 0; i < nworkers; i++) {
        SSL_SESSION_free(workers[i].w_session);
        sa_free(&workers[i].w_sa);
    }
    free(workers);
    SSL_CTX_free(ctx);

    return (int)exit_code;
}
