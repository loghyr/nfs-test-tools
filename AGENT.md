<!-- SPDX-License-Identifier: Apache-2.0 -->

# nfs-test-tools: AI Agent Guide for Output Analysis

This document tells an AI agent (or AI-assisted QA tester) how to
analyze the output of `nfs_tls_test` and `nfs_krb5_test`.  Each section
below maps tool output to a verdict and diagnosis.

Quick analysis: pipe output through `scripts/analyze_nfs_results.py`
(exit 0 = PASS, 1 = FAIL, 2 = WARN) and read the structured report.
This document explains what the script checks and why.

---

## CLI Quick Reference

### nfs_tls_test flags

| Flag | Argument | Default | Purpose |
|------|----------|---------|---------|
| `--host` | HOST | (required) | NFS server hostname or IP |
| `--port` | PORT | 2049 | TCP port |
| `--iterations` | N | 10 | Connections per thread (or per duration) |
| `--ca-cert` | FILE | — | CA certificate PEM; skip verify if absent |
| `--cert` | FILE | — | Client certificate PEM (mutual TLS) |
| `--key` | FILE | — | Client private key PEM (mutual TLS) |
| `--no-null` | — | off | Skip post-handshake NULL RPC |
| `--verbose` | — | off | Print per-connection details (single-thread only) |
| `--threads` | N | 1 | Concurrent worker threads |
| `--duration` | N | — | Run for N seconds (overrides `--iterations`) |
| `--calls-per-conn` | N | 1 | NULL RPCs per TLS connection |
| `--no-session-reuse` | — | off | Force full TLS handshake each time |
| `--rate` | N | unlimited | Target connections/s |
| `--progress` | N | 10 | Progress interval seconds (0 = off) |
| `--tls-info` | — | off | Print negotiated TLS version/cipher/ALPN |
| `--histogram` | — | off | Print ASCII latency histogram |
| `--snapshot-stats` | — | off | Read `/proc/net/tls_stat` before/after |
| `--output` | text\|json | text | Report format |
| `--keylog` | FILE | — | NSS-format TLS key log for Wireshark |
| `--check-san` | LIST | — | Require server cert SAN entries (comma-separated `IP:...,DNS:...`) |
| `--require-tls13` | — | off | Treat TLS < 1.3 as failure |
| `--require-alpn` | NAME | sunrpc | Require this ALPN protocol |
| `--diagnose` | — | — | Run local pre-flight checks and exit |
| `--print-error-table` | — | — | Print TLS error taxonomy and exit |

### nfs_krb5_test flags

| Flag | Argument | Default | Purpose |
|------|----------|---------|---------|
| `--host` | HOST | (required) | NFS server hostname or IP |
| `--port` | PORT | 2049 | TCP port |
| `--principal` | SPN | (required) | Service principal: `nfs/HOST@REALM` or `nfs@HOST` |
| `--iterations` | N | 1 | GSS context + NULL call repetitions |
| `--sec` | FLAVOR | krb5 | Security flavor: `krb5` (auth), `krb5i` (integrity), `krb5p` (privacy) |
| `--probe-secinfo` | — | off | Two-step SECINFO probe (no TGT needed); exits before GSS setup |
| `--threads` | N | — | Spawn N workers (1-256), each with its own GSS context |
| `--stress` | — | off | Run all iterations past failures; emit per-code totals |
| `--verbose` | — | off | Show GSS exchange details |
| `--krb5-trace` | FILE | — | Set `KRB5_TRACE` for libkrb5 tracing (this process only) |
| `--diagnose` | — | — | Run local pre-flight krb5 checks and exit |
| `--print-error-table` | — | — | Print krb5 error taxonomy and exit |

### Exit codes

#### nfs_tls_test

| Code | Phase | Meaning |
|------|-------|---------|
| 0 | — | All connections succeeded |
| 10-15 | PRE_FLIGHT | `--diagnose` found a local config problem |
| 20-22 | TCP | Connection refused, timeout, or DNS failure |
| 30-32 | PROBE | AUTH_TLS probe rejected or malformed reply |
| 40-50 | HANDSHAKE | TLS cert/cipher/ALPN/version error |
| 60-61 | RPC | NULL RPC failed after TLS established |
| 70-72 | KTLS | kTLS counter anomaly (decrypt error, rekey error, no-pad violation) |
| 90 | — | MIXED: multiple distinct failure classes |
| 99 | — | INTERNAL: tool/transport bug; file an issue |

The exit code is the **lowest-numbered** phase that had failures,
except when multiple phases fail: then 90 (MIXED).

#### nfs_krb5_test

| Code | Range | Phase | Meaning |
|------|-------|-------|---------|
| 0 | — | — | Success |
| 100-109 | PRE_FLIGHT | — | Local environment: krb5.conf, keytab, gssd, FQDN |
| 120-134 | KERBEROS | — | KDC / TGT / key version / enctype errors |
| 150-159 | GSS | — | GSS-API layer errors (bad name, no cred, bad MIC) |
| 170-179 | RPCSEC_GSS | — | Wire RPCSEC_GSS failures, WRONGSEC, replay |
| 190-193 | IDMAP | — | Identity mapping failures |
| 250 | — | MIXED | `--stress` run had more than one failure class |

Use `--print-error-table` to see all codes and their fix suggestions.

### [ERROR SYMBOL] block format

Both tools write this block to stderr whenever a classified error occurs
(always in `--stress` mode, at first failure in default mode):

```
[ERROR SYMBOL_NAME]  (context string)
    One-line description of what went wrong.
    Fix: what to do to resolve it.
    See: TROUBLESHOOTING.md#section
```

The `SYMBOL_NAME` is a stable machine-readable token (e.g.,
`KRB5_ERR_CLOCK_SKEW`, `TLS_ERR_CERT_EXPIRED`).  `analyze_nfs_results.py`
parses these blocks to extract the verdict.

In `--stress` mode, the context string shows the count:
```
[ERROR KRB5_ERR_RPCSEC_REPLAY]  (3 stress failures)
    Server rejected seq_num as a replay.
    Fix: server replay cache is too small or clock diverged mid-run.
    See: TROUBLESHOOTING.md#rpcsec-replay
```

### --threads N output (nfs_krb5_test)

Each worker reports its own result line after joining.  A summary
follows:

```
thread 1: PASS (1 ok)
thread 2: PASS (1 ok)
thread 3: FAIL [ERROR KRB5_ERR_RPCSEC_REPLAY]
thread 4: PASS (1 ok)

threads: 4 total, 3 ok, 1 fail
FAIL
```

The process exit code reflects the dominant failure class across all
workers (or 250/MIXED if workers hit different error classes).

### --probe-secinfo output (nfs_krb5_test)

`--probe-secinfo` does not require a TGT.  It connects with AUTH_SYS
and runs a two-step NFSv4 COMPOUND per RFC 5661 S18.45.5:

```
probe: step 1 AUTH_SYS NULL -> OK
probe: step 2 PUTROOTFH + SECINFO_NO_NAME -> OK
  flavors advertised: 6 (rpc_gss_svc_none) 390003 1 (sys)
  --sec krb5 (6): PRESENT
PASS
```

The exit code is 0 (PASS) if AUTH_SYS is accepted and the server
responded.  A non-zero exit means the server refused AUTH_SYS on the
root compound (NFS4ERR_WRONGSEC or connection failure) -- Kerberos
negotiation cannot proceed.  Common exit codes in this path:
`KRB5_ERR_WRONGSEC` (177) or `KRB5_ERR_SECINFO_EMPTY` (178).

### analyze_nfs_results.py

Parses captured stdout+stderr from either tool and exits
0 (PASS), 1 (FAIL), or 2 (WARN).

```bash
# Pipe directly
./src/nfs_tls_test --host SERVER --threads 4 --iterations 1000 \
    --tls-info 2>&1 | scripts/analyze_nfs_results.py

# From a saved file
scripts/analyze_nfs_results.py results.txt

# Loosen latency thresholds for a cross-datacenter run
scripts/analyze_nfs_results.py \
    --warn-handshake-p99 150 \
    --fail-handshake-p99 800 \
    --warn-total-p99 400 \
    --fail-total-p99 2000 \
    results.txt
```

Available threshold flags (all in ms unless noted):

| Flag | Default | Meaning |
|------|---------|---------|
| `--warn-tcp-p99` | 10 | WARN if tcp p99 exceeds this |
| `--fail-tcp-p99` | 50 | FAIL if tcp p99 exceeds this |
| `--warn-handshake-p99` | 100 | WARN if handshake p99 exceeds this |
| `--fail-handshake-p99` | 500 | FAIL if handshake p99 exceeds this |
| `--warn-total-p99` | 200 | WARN if total p99 exceeds this |
| `--fail-total-p99` | 1000 | FAIL if total p99 exceeds this |
| `--warn-session-reuse` | 50 | WARN if session reuse rate below this % |

---

## nfs_tls_test

### What it tests

RFC 9289 STARTTLS over NFS (port 2049 by default).  The tool opens N
concurrent TCP connections to the server, negotiates TLS via the
`AUTH_TLS` RPC probe, then sends NULL RPCs over the encrypted channel.
Each connection is broken into phases: TCP connect, AUTH_TLS probe,
TLS handshake, NFS NULL RPC.

### Pass/fail decision tree

Ask these questions in order.  Stop at the first failure.

1. **Did the process exit non-zero?**
   Yes -> FAIL.  The binary exits non-zero only on hard errors (bad args,
   no connections completed, SSL_CTX creation failure).  The ASCII report
   was not printed; check stderr for the error message.

2. **Is `fail` count > 0 on the `Total connections` line?**
   ```
   Total connections: 1000 ok, 0 fail       <- PASS
   Total connections: 995 ok, 5 fail        <- FAIL: see Error breakdown
   ```
   Any failure is a FAIL unless it is a known transient (see Failure
   patterns below).

3. **Is `Error breakdown` all zeros?**
   ```
   Error breakdown: 0 tcp, 0 probe, 0 handshake, 0 rpc   <- PASS
   Error breakdown: 0 tcp, 3 probe, 0 handshake, 0 rpc   <- FAIL
   ```
   Non-zero in any phase is a FAIL.  The phase identifies the server
   component at fault (see Phase diagnosis below).

4. **Is TLS version TLSv1.3?**
   ```
   TLS: TLSv1.3, TLS_AES_256_GCM_SHA384, X25519     <- PASS
   TLS: TLSv1.2, ECDHE-RSA-AES256-GCM-SHA384, P-256 <- WARN: TLS 1.2
   ```
   TLSv1.2 is a WARN (not a FAIL) unless the server is configured to
   require 1.3.  Report the negotiated version and cipher to the user.

5. **Are handshake latencies within acceptable bounds?**

   | Phase       | WARN threshold | FAIL threshold |
   |-------------|---------------|----------------|
   | tcp p99     | > 10 ms       | > 50 ms        |
   | handshake p99 | > 100 ms    | > 500 ms       |
   | total p99   | > 200 ms      | > 1000 ms      |

   Defaults are conservative.  Adjust for the network (local loopback
   vs. cross-datacenter).

6. **Is the session reuse rate reasonable?**
   ```
   Sessions: 847 resumed, 153 full handshake    <- 85% reuse rate
   ```
   If `--no-session-reuse` was NOT passed, a reuse rate below 50% is a
   WARN (session cache may be misconfigured or disabled on the server).
   0% reuse with session reuse enabled is a FAIL.

If all six checks pass: overall verdict is PASS.

### Phase diagnosis

When `Error breakdown` shows non-zero failures, map the phase to the
server component responsible:

| Phase | Failures mean | Where to look |
|-------|--------------|---------------|
| `tcp` | TCP connection refused or timeout | Server down, firewall, wrong port, overloaded listen queue |
| `probe` | AUTH_TLS probe rejected or malformed reply | Server's RFC 9289 implementation; try `--verbose` to see wire exchange |
| `handshake` | TLS handshake failed | Certificate (expired, wrong CN, CA mismatch), ALPN missing "sunrpc", cipher mismatch; add `--ca-cert` if using custom CA |
| `rpc` | NULL RPC failed after TLS established | Server NFS stack not responding post-TLS; check server logs |

### Interpreting the phase breakdown table

```
  Phase breakdown (ms):
                  p50     p95     p99    p99.9     avg     min     max
  tcp           0.41    0.89    1.23     3.12    0.44    0.21    4.01
  probe         0.28    0.61    0.94     2.10    0.30    0.18    2.88
  handshake     1.84    3.21    5.67    12.44    1.91    0.91   14.33
  rpc           0.19    0.38    0.62     1.21    0.20    0.11    1.89
  total         2.81    5.12    8.44    18.91    2.93    1.48   20.11
```

- **p50** -- median; reflects typical client experience.
- **p95, p99** -- tail latency; what 5% and 1% of clients experience
  respectively.  This is the primary SLA metric.
- **p99.9** -- worst-case tail; relevant for high-concurrency or
  long-duration runs.
- **max** -- single worst observation.  If max >> p99.9 by more than
  10x, investigate outliers (GC pauses, kernel scheduling, TCP
  retransmits).
- **avg** -- useful for capacity planning only; not useful for SLA.
- **handshake** -- typically dominates total latency.  If tcp is
  unusually high (> 5ms p50 on a local network), suspect network or
  server resource exhaustion.

### Comparing two runs

When comparing a reffs run to a reference (e.g., Linux knfsd):

1. Check that both runs used the same flags (threads, iterations,
   session reuse settings).
2. Compare `Sessions: N resumed, M full` ratios -- both should match
   if the test was the same.
3. Compare p50/p99 for each phase.  A 10-20% difference is noise.
   A 2x or greater difference in handshake p99 warrants investigation.
4. Error counts should be 0 for both; any discrepancy is a FAIL on the
   higher side.

### Common patterns and their meanings

| Pattern | Cause |
|---------|-------|
| `0 fail` but high `max` (>> p99.9 by 100x) | Single outlier: TCP retry, server GC, or scheduling jitter.  Not a protocol bug.  Note it. |
| All-or-nothing failures (e.g., 0 ok after several ok) | Server restarted mid-run, or resource limit hit (open files, threads). |
| `probe` failures only | Server does not support RFC 9289 STARTTLS; check server config. |
| `handshake` failures only, `probe` ok | TLS configuration mismatch: wrong CA, expired cert, no "sunrpc" ALPN. |
| `tcp` failures with high p99 tcp | Server hit accept queue limit; try lower `--rate` or fewer `--threads`. |
| 0% session reuse with reuse enabled | Server has disabled TLS session cache or is using a ticket-only mode without the client matching tickets; check server TLS config. |
| p99.9 / max spike at low concurrency | Look for `--verbose` on a single-thread run; that will show the slow iteration. |

---

## nfs_krb5_test

### What it tests

RPCSEC_GSS (RFC 2203) context establishment and authenticated NFS NULL
calls using Kerberos 5.  The tool runs the full GSS INIT / CONTINUE_INIT
token exchange, verifies the server's reply MIC, then issues N NULL calls
with GSS DATA mode.

### Pass/fail decision tree

1. **Did the process exit non-zero?**
   Yes -> FAIL.  The tool prints `FAIL` as its last line on stderr.

2. **Is the last line of stdout `PASS` or `FAIL`?**
   ```
   PASS   <- PASS
   FAIL   <- FAIL
   ```
   This is the single authoritative verdict.

3. **If FAIL: which step failed?**
   Run with `--verbose` to see the full GSS token exchange.

### Failure step diagnosis

The tool prints one line per step.  The line that is absent (or
replaced by an error) is where it failed:

| Missing or error line | Cause |
|-----------------------|-------|
| `connect:` error | Server not reachable: wrong host/port, firewall, server down |
| `gss_import_name` | Invalid `--principal` syntax; should be `nfs/hostname@REALM` or `nfs@hostname` |
| `gss_init_sec_context: maj=N min=M` | Kerberos error: no TGT (`kinit` needed), wrong realm, keytab expired, clock skew > 5 min, or wrong service principal on server |
| `INIT reply: ... done=0` repeating | GSS multi-step failing; server keytab mismatch |
| Context established but NULL call fails | Server NFS stack not dispatching authenticated calls; check server logs |

### Decoding GSS major/minor status

`gss_init_sec_context` errors report `maj=N min=M`.  Common values:

| Major status | Meaning |
|--------------|---------|
| 851968 (0xD0000) | `GSS_S_NO_CRED` -- no credentials (run `kinit`) |
| 458752 (0x70000) | `GSS_S_BAD_NAME` -- principal name rejected |
| 131072 (0x20000) | `GSS_S_BAD_MECH` -- mechanism not supported |
| 393216 (0x60000) | `GSS_S_FAILURE` -- generic; check minor status |
| 589824 (0x90000) | `GSS_S_NO_CONTEXT` -- no context (server-side issue) |

Minor status is Kerberos-specific; pass it to `com_err` or look it
up in `<gssapi/gssapi_krb5.h>`.  The most common minor errors:
- Clock skew > 5 minutes: sync clocks with NTP
- Server keytab missing / expired: regenerate and deploy keytab
- Wrong SPN: verify `--principal` matches the keytab on the server

### Typical healthy output (verbose)

```
nfs_krb5_test: server:2049 principal=nfs/server@REALM
  gss_import_name OK
  gss_init_sec_context: out_token=1234 bytes gss_proc=1
  INIT reply: handle_len=16 done=0
  gss_init_sec_context: out_token=256 bytes gss_proc=2
  INIT reply: handle_len=16 done=1
  RPCSEC_GSS context established (handle_len=16)
  DATA NULL [1]: OK (seq=1)
  DATA NULL [2]: OK (seq=2)
  NULL call 1/2 OK
  NULL call 2/2 OK
PASS
```

Two GSS rounds is normal for Kerberos 5 (INIT + one CONTINUE).

---

## Running on a server under test

For server setup instructions (server requirements, certificate
configuration, NFSv3 vs NFSv4 compatibility), see `README.md`.

### Minimal TLS check (correctness only)

```bash
./src/nfs_tls_test --host SERVER --iterations 10 --tls-info
```

For NFSv3-only servers (no NFSv4 support), add `--no-null` to skip
the post-handshake NULL RPC (which uses NFS_VERSION_4 in its header)
and test only the STARTTLS exchange and TLS handshake:

```bash
./src/nfs_tls_test --host SERVER --iterations 10 --tls-info --no-null
```

### Stress test (concurrent, with session reuse and histogram)

```bash
./src/nfs_tls_test --host SERVER \
    --threads 8 --duration 60 \
    --tls-info --histogram \
    --progress 10
```

### Kerberos check (requires `kinit` first)

```bash
kinit user@REALM
./src/nfs_krb5_test --host SERVER --principal nfs/SERVER@REALM \
    --iterations 5 --verbose
```

### Automated analysis

```bash
./src/nfs_tls_test --host SERVER --threads 4 --iterations 1000 \
    --tls-info 2>&1 | scripts/analyze_nfs_results.py
echo "Exit: $?"   # 0=PASS 1=FAIL 2=WARN

./src/nfs_krb5_test --host SERVER --principal nfs/SERVER@REALM \
    2>&1 | scripts/analyze_nfs_results.py
```

Or save output to a file first:

```bash
./src/nfs_tls_test ... > tls_results.txt 2>&1
scripts/analyze_nfs_results.py tls_results.txt
```

---

## What to report to the user

When summarizing a test run, include:

1. **Tool and flags used** (so the run can be reproduced)
2. **Overall verdict**: PASS / WARN / FAIL
3. **If PASS**: TLS version negotiated, total connections, p50/p99 total
   latency, session reuse percentage
4. **If WARN**: Which threshold triggered, measured value vs. threshold,
   suggested investigation
5. **If FAIL**: Which phase failed, error count, verbatim error lines from
   the output, and the likely cause from the Phase diagnosis table above
6. **Comparison note** (if comparing to a baseline): delta in p50/p99 for
   each phase, whether error counts differ

### Example PASS summary

```
nfs_tls_test against reffs.ci:2049 (4 threads, 1000 iterations):
  PASS
  TLS: TLSv1.3, TLS_AES_256_GCM_SHA384, X25519
  Sessions: 847 resumed (84.7%), 153 full handshake
  Total: 1000 ok, 0 fail
  Latency (total): p50=2.8ms, p99=8.4ms, max=20ms
  Handshake:       p50=1.8ms, p99=5.7ms
```

### Example FAIL summary

```
nfs_tls_test against reffs.ci:2049 (4 threads, 1000 iterations):
  FAIL -- 3 handshake failures
  Error breakdown: 0 tcp, 0 probe, 3 handshake, 0 rpc
  Likely cause: TLS certificate mismatch or expired cert.
  Next step: run with --ca-cert and --verbose to see SSL error.
```
