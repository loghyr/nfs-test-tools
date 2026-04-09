<!-- SPDX-License-Identifier: Apache-2.0 -->

# nfs-test-tools: AI Agent Guide for Output Analysis

This document tells an AI agent (or AI-assisted QA tester) how to
analyze the output of `nfs_tls_test` and `nfs_krb5_test`.  Each section
below maps tool output to a verdict and diagnosis.

Quick analysis: pipe output through `scripts/analyze_nfs_results.py`
(exit 0 = PASS, 1 = FAIL, 2 = WARN) and read the structured report.
This document explains what the script checks and why.

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

### Minimal TLS check (correctness only)

```bash
./src/nfs_tls_test --host SERVER --iterations 10 --tls-info
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
