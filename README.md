<!-- SPDX-License-Identifier: Apache-2.0 -->

# nfs-test-tools -- protocol-level NFS test utilities

A collection of tools for testing NFS server implementations at
the protocol level: TLS/STARTTLS stress, Kerberos authentication
verification, mount exerciser, and RPC diagnostics.

## Tools

| Tool | Purpose |
|------|---------|
| `nfs_tls_test` | TLS and STARTTLS (RFC 9289) stress testing |
| `nfs_krb5_test` | Kerberos/RPCSEC_GSS authentication verification |

## Build

```bash
mkdir -p m4 && autoreconf -fi
mkdir -p build && cd build
../configure
make -j$(nproc)
```

Requires OpenSSL (libssl, libcrypto) for `nfs_tls_test`.
Requires MIT Kerberos (libgssapi_krb5) for `nfs_krb5_test`.

---

## nfs_tls_test

### What it tests

`nfs_tls_test` tests RFC 9289 RPC-over-TLS (STARTTLS) at the
transport layer.  It does NOT test NFS file operations.  Each
connection goes through four phases:

1. **TCP connect** to the server on the NFS port
2. **AUTH_TLS probe** -- sends a special NULL RPC with the AUTH_TLS
   credential (flavor 7) to ask the server to begin TLS negotiation
3. **TLS handshake** with ALPN "sunrpc" (required by RFC 9289)
4. **NFS NULL RPC** over the encrypted channel to confirm the
   encrypted channel works end-to-end

The tool measures latency for each phase and reports statistics
across all connections.

### NFS version compatibility

The STARTTLS mechanism in RFC 9289 is transport-level and applies
to both NFSv3 and NFSv4.  However, the post-handshake NULL RPC
(phase 4) uses `NFS_VERSION_4` in its RPC header.

| Server type | Behavior | Recommendation |
|------------|----------|----------------|
| NFSv4 or NFSv4.2 | All four phases work | Use default flags |
| NFSv3 only (no v4) | Phase 4 NULL RPC may return PROG_MISMATCH or be ignored | Use `--no-null` to test phases 1-3 only |
| Both NFSv3 and NFSv4 | All four phases work | Use default flags |

`--no-null` skips phase 4 entirely, testing only the STARTTLS
exchange and TLS handshake.  This is sufficient to verify that a
server's TLS setup is correct.

### Server requirements

The server must:

1. Support RFC 9289 STARTTLS (not raw TLS on a separate port)
2. Have a valid TLS certificate
3. Configure TLS 1.3 (the tool enforces TLS 1.3 minimum)
4. Negotiate ALPN protocol "sunrpc"

#### Linux knfsd setup (reference)

```bash
# Install ktls-utils (provides tlshd)
dnf install ktls-utils          # Fedora/RHEL
apt install ktls-utils          # Ubuntu 23.04+

# Generate a certificate for the server (self-signed example)
openssl req -x509 -newkey rsa:4096 -keyout /etc/nfs-server.key \
  -out /etc/nfs-server.pem -days 365 -nodes \
  -subj "/CN=$(hostname)" -addext "subjectAltName=IP:$(hostname -I | awk '{print $1}')"

# Configure tlshd: /etc/tlshd.conf
# [server-authentication]
# x509.certificate=/etc/nfs-server.pem
# x509.private_key=/etc/nfs-server.key

# Enable TLS in nfsd: /etc/nfs.conf
# [nfsd]
# tls=y

# Start services
systemctl enable --now tlshd
systemctl restart nfs-server
```

#### reffs setup

reffs enables TLS via the TOML config and the probe protocol:

```toml
[server]
tls_cert = "/etc/reffs/server.pem"
tls_key  = "/etc/reffs/server.key"

[[export]]
path = "/tls"
flavors = ["tls"]
```

### Client-side setup

The tool needs no special configuration beyond optionally a CA
certificate for server verification.

#### Quick test (no certificate verification)

Without `--ca-cert`, the tool skips server certificate verification
(equivalent to `curl -k`).  This is useful for an initial
connectivity check:

```bash
./nfs_tls_test --host SERVER
```

This verifies:
- The server responds to AUTH_TLS probe (RFC 9289 support)
- TLS handshake succeeds with ALPN "sunrpc"
- TLS 1.3 is negotiated
- A NULL RPC works over the encrypted channel

#### With certificate verification

```bash
./nfs_tls_test --host SERVER --ca-cert /path/to/ca.pem
```

The tool verifies the server's certificate against the provided CA.
For self-signed server certificates, use the server's own certificate
as the CA cert.

#### Mutual TLS (client certificate)

```bash
./nfs_tls_test --host SERVER \
  --ca-cert /path/to/ca.pem \
  --cert /path/to/client.pem \
  --key  /path/to/client.key
```

### Common usage examples

#### Minimal connectivity check

```bash
./nfs_tls_test --host SERVER
```

#### Correctness only (10 connections, show TLS info)

```bash
./nfs_tls_test --host SERVER --iterations 10 --tls-info
```

#### Stress test (concurrent, with session reuse and histogram)

```bash
./nfs_tls_test --host SERVER \
  --threads 8 --duration 60 \
  --tls-info --histogram \
  --progress 10
```

#### NFSv3-only server (skip NULL RPC)

```bash
./nfs_tls_test --host SERVER --iterations 100 --no-null
```

#### With certificate verification and latency thresholds

```bash
./nfs_tls_test --host SERVER \
  --ca-cert /etc/nfs-ca.pem \
  --threads 4 --iterations 1000 \
  --tls-info
```

### Diagnostic and debugging options

For when something is broken and you need more than latencies:

#### Local pre-flight checks

Before debugging a connection, check the local system:

```bash
./nfs_tls_test --diagnose
```

Verifies kernel version, `CONFIG_SUNRPC_TLS`, the `tls` module,
`tlshd` presence and runtime state, and OpenSSL version.  Emits a
structured PASS/FAIL/WARN report.  No network IO; no `--host`
required.

#### Decrypt the wire with Wireshark

```bash
./nfs_tls_test --host SERVER --keylog /tmp/keylog.txt
```

Writes NSS-format TLS session keys to `/tmp/keylog.txt`.  Capture
traffic with `tcpdump`/`tshark` separately, then point Wireshark at
the keylog file (`Edit -> Preferences -> Protocols -> TLS ->
(Pre)-Master-Secret log filename`) to see decrypted RPC and NFS
content.

#### Verify server certificate SAN

```bash
./nfs_tls_test --host SERVER \
  --check-san "IP:10.0.0.1,DNS:nfs.example.com"
```

After the handshake, verifies that the server's leaf certificate
SAN includes every required entry.  A missing entry counts as a
handshake-phase failure.

#### Watch kernel TLS counters

```bash
./nfs_tls_test --host SERVER --threads 4 --duration 60 \
  --snapshot-stats
```

Reads `/proc/net/tls_stat` before and after the run and prints
deltas.  Any non-zero `TlsDecryptError`, rekey errors, or
no-pad violations are flagged and folded into the exit status --
a passing functional test that increments these counters is a real
failure that latency-only monitoring would miss.

#### Strict-mode enforcement

```bash
./nfs_tls_test --host SERVER --require-tls13 --require-alpn sunrpc
```

Promotes any TLS version below 1.3 from a WARN to a hard FAIL, and
requires a specific ALPN protocol (default check is already
`sunrpc` per RFC 9289; this lets you enforce arbitrary protocols
for non-NFS testing).

#### JSON output for CI integration

```bash
./nfs_tls_test --host SERVER --output json
```

Emits a single JSON object instead of the human-readable report.
The shape is documented in `--help` and is intended to be parsed
by downstream CI tooling without scraping the ASCII format.

#### Symbolic exit codes and error reference

When a run fails, `nfs_tls_test` prints one or more `[ERROR SYMBOL]`
blocks pointing at the matching section of `TROUBLESHOOTING.md`:

```
Most likely causes (see TROUBLESHOOTING.md for details):
[ERROR HANDSHAKE_FAILED]  (10 handshake failures)
    TLS handshake failed for an unspecified reason
    Fix: Run with --keylog and decrypt the capture in Wireshark
    See: TROUBLESHOOTING.md#handshake_failed
```

The exit status is the symbolic code's numeric value (`0` on success,
`90` for `MIXED` if more than one failure class occurred, otherwise
the dominant phase's stable code: `20`/`21`/`22` for TCP, `30`/`31`/`32`
for probe, `40`-`50` for handshake, `60`/`61` for RPC, `70`-`72` for
kTLS counter errors).

The full canonical taxonomy is dumped by:

```bash
./nfs_tls_test --print-error-table
```

The `SYMBOL` and `#anchor` are stable identifiers from
`src/tls_error.h` -- safe to match on in CI scripts and bug reports.

---

## nfs_tls_server

A minimal RFC 9289 STARTTLS server for testing client implementations.
Listens on a TCP port, accepts AUTH_TLS NULL probes, performs the
TLS handshake with ALPN `sunrpc`, and replies to NULL RPCs over the
encrypted channel.

This is the mirror of `nfs_tls_test` on the server side: instead of
driving connections at a server, it accepts connections from a client
being tested.  Useful for verifying RFC 9289 client implementations
(`tlshd`, FreeBSD `rpc.tlsclntd`, custom user-space clients) without
needing a full NFS server stack.

```bash
# Generate a self-signed cert for the server
openssl req -x509 -newkey rsa:4096 \
  -keyout /tmp/server.key -out /tmp/server.pem \
  -days 30 -nodes -subj "/CN=test-server" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

# Run the server
./nfs_tls_server --cert /tmp/server.pem --key /tmp/server.key \
                 --port 12049 --verbose

# In another shell, test it with the client
./nfs_tls_test --host 127.0.0.1 --port 12049 \
               --ca-cert /tmp/server.pem --tls-info
```

For mutual TLS, supply `--ca-cert` and optionally `--require-mtls`.

The server is single-threaded by design -- one client at a time --
to keep it trivially debuggable and avoid concurrency complexity in
a tool whose job is to expose protocol conformance bugs.

---

## nfs_cert_info

A standalone certificate validation tool: load a PEM cert (and
optionally a key, CA bundle, and required SAN entries) and emit a
structured report without performing any network IO.  This is the
openssl-equivalent of the certificate troubleshooting commands in
`TROUBLESHOOTING.md`, packaged as one tool invocation.

```bash
# Basic inspection
./nfs_cert_info --cert /etc/nfs/server.pem

# Verify cert/key pair match
./nfs_cert_info --cert /etc/nfs/server.pem --key /etc/nfs/server.key

# Verify against a CA bundle
./nfs_cert_info --cert /etc/nfs/server.pem --ca /etc/nfs/ca.pem

# Require specific SAN entries
./nfs_cert_info --cert /etc/nfs/server.pem \
  --require-san "IP:10.0.0.1,DNS:nfs.example.com"

# Everything together
./nfs_cert_info \
  --cert /etc/nfs/server.pem \
  --key  /etc/nfs/server.key \
  --ca   /etc/nfs/ca.pem \
  --require-san "IP:10.0.0.1,DNS:nfs.example.com"
```

Exit codes: 0 = PASS, 1 = FAIL, 2 = WARN.

Useful for cron-driven cert expiration monitoring and pre-deployment
validation -- catches expired certs, missing SAN entries, broken cert
chains, and key/cert mismatches without ever opening a socket.

---

### Analyzing results

Pipe output through `scripts/analyze_nfs_results.py` for a
structured verdict (exit 0=PASS, 1=FAIL, 2=WARN):

```bash
./nfs_tls_test --host SERVER --threads 4 --iterations 1000 \
  --tls-info 2>&1 | scripts/analyze_nfs_results.py

echo "Verdict: $?"
```

Or save to a file:

```bash
./nfs_tls_test --host SERVER --threads 4 --iterations 1000 \
  --tls-info > results.txt 2>&1
scripts/analyze_nfs_results.py results.txt
```

See `AGENT.md` for a full description of the output format, failure
diagnosis, and what to report.

---

## nfs_krb5_test

### What it tests

`nfs_krb5_test` tests RPCSEC_GSS (RFC 2203) context establishment
and authenticated NFS NULL calls using Kerberos 5.  It requires
a valid Kerberos TGT on the client and a correctly configured
keytab on the server.

### Server requirements

1. A Kerberos 5 service principal `nfs/hostname@REALM` in the
   server's keytab (typically `/etc/krb5.keytab`)
2. For Linux knfsd: `rpc.svcgssd` running (or systemd unit
   `nfs-server.service` with Kerberos configured)
3. An NFS export with `sec=krb5` (or `krb5i`, `krb5p`)

### Client-side setup

1. A valid Kerberos TGT:
   ```bash
   kinit user@REALM
   klist              # verify ticket
   ```

2. The server's KDC reachable from the client

### Usage

```bash
# Basic authentication check (sec=krb5, auth only)
./nfs_krb5_test --host SERVER --principal nfs/SERVER@REALM

# Verbose (shows full GSS token exchange)
./nfs_krb5_test --host SERVER --principal nfs/SERVER@REALM --verbose

# Multiple NULL calls
./nfs_krb5_test --host SERVER --principal nfs/SERVER@REALM \
  --iterations 5 --verbose
```

#### Service flavor coverage (krb5 / krb5i / krb5p)

```bash
# Integrity: SVC_INTEG, MIC over RPC arguments per RFC 2203 S5.3.2
./nfs_krb5_test --host SERVER --sec krb5i

# Privacy: SVC_PRIV, gss_wrap of RPC arguments per RFC 2203 S5.3.3
./nfs_krb5_test --host SERVER --sec krb5p
```

The default `krb5` flavor only proves the authenticator works
(MIC over the call header).  `--sec krb5i` and `--sec krb5p`
exercise integrity and privacy services respectively, with
gss_get_mic / gss_unwrap on the reply body.  Versions of this
tool prior to the RFC 2203 wire-format work tested only `krb5` --
the `--sec` flag is the canonical way to verify a server's full
RPCSEC_GSS implementation.

#### Pre-flight checks

```bash
./nfs_krb5_test --diagnose
```

Runs seven local checks without touching the network:
`/etc/krb5.conf` parse, keytab presence and readability, `nfs/`
principal in the keytab, user TGT in the ccache, gssproxy or
rpc.gssd running, nfsidmap installed, FQDN hostname, forward+
reverse DNS round-trip.  Exit status: 0 = PASS, 1 = FAIL,
2 = WARN.

#### libkrb5 trace capture

```bash
./nfs_krb5_test --host SERVER --krb5-trace /tmp/krb5.log --verbose
```

Sets `KRB5_TRACE` for THIS process so libkrb5 writes its trace
lines to the named file.  Captures only this binary's libkrb5
calls -- mount-time failures live in `rpc.gssd` / `gssproxy` and
need `rpcdebug -m rpc -s auth` plus `journalctl -u rpc-gssd -f`
instead.

#### Stress mode (replay-cache thrash, single context)

```bash
./nfs_krb5_test --host SERVER --sec krb5p \
  --iterations 10000 --stress
```

Runs all `--iterations` calls on a single context regardless of
intermittent failures, churning seq_num against the server's
RPCSEC_GSS replay window.  Reports per-symbolic-code totals at
the end and exits with the dominant code (or `250` MIXED if more
than one class fails).

#### Multi-worker stress mode (concurrent contexts)

```bash
./nfs_krb5_test --host SERVER --threads 8 \
  --iterations 100 --sec krb5i
```

Spawns N worker threads (1..256); each establishes its own independent
RPCSEC_GSS context and runs `--iterations` NULL calls concurrently.
Exercises the server's per-context replay cache under load from N
simultaneous GSS handles rather than one churned seq_num.  Aggregate
results (ok count, per-symbol-code failure counts) are reported after
all workers join, using the same taxonomy as `--stress`.

Combine with `--stress` to run all iterations past failures within
each worker:

```bash
./nfs_krb5_test --host SERVER --threads 8 \
  --iterations 1000 --stress --sec krb5p
```

#### SECINFO probe (pre-Kerberos connectivity check)

```bash
./nfs_krb5_test --host SERVER --probe-secinfo
```

Sends a two-step NFSv4 COMPOUND using `AUTH_SYS` (no Kerberos or TGT
required):

1. **Step 1** -- bare NULL COMPOUND to check whether the server accepts
   `AUTH_SYS` at all.  If it returns `NFS4ERR_WRONGSEC`, the server
   refuses `AUTH_SYS` even for this probe, which is an RFC 5661
   §18.45.5 violation (the spec requires PUTROOTFH + SECINFO_NO_NAME
   to succeed with `AUTH_SYS`).

2. **Step 2** -- `PUTROOTFH + SECINFO_NO_NAME` to list the security
   flavors the server advertises for the root export.  Reports which
   flavors are present and whether the `--sec` target flavor is among
   them.

Exits after the probe without attempting Kerberos context setup.
Useful for diagnosing `NFS4ERR_WRONGSEC` before you have a valid TGT,
or to confirm a server's security policy before `kinit`.

#### Symbolic exit codes

When `nfs_krb5_test` detects a failure it prints one or more
`[ERROR SYMBOL]` blocks pointing at the matching section of
`TROUBLESHOOTING.md`:

```
[ERROR CLOCK_SKEW]  (gss_init_sec_context: maj=0xd0000 min=0x96c73a25)
    Clock skew vs the KDC exceeds the allowed window (default 5 min)
    Fix: Sync system clocks via chrony / systemd-timesyncd on both ends
    See: TROUBLESHOOTING.md#clock_skew
```

The exit status is the symbolic code's numeric value (`100..199`
for krb5-domain failures, `0` on success, `250` for `MIXED`).
The full canonical taxonomy is dumped by:

```bash
./nfs_krb5_test --print-error-table
```

The `SYMBOL` and `#anchor` are stable identifiers from
`src/krb5_error.h` -- safe to match on in CI scripts and bug
reports.

### Analyzing results

```bash
./nfs_krb5_test --host SERVER --principal nfs/SERVER@REALM \
  2>&1 | scripts/analyze_nfs_results.py
```

The analyzer extracts the `[ERROR SYMBOL]` blocks regardless of
which tool produced the output, and surfaces them as
`krb5_<symbol_lower>` / `tls_<symbol_lower>` findings in its
verdict.  See `TROUBLESHOOTING.md#nfs-over-kerberos` for the full
debugging guide and per-symbol playbooks.

---

## Output analysis

`scripts/analyze_nfs_results.py` -- automated result analysis:

```
Exit 0: PASS
Exit 1: FAIL
Exit 2: WARN
```

Usage:

```bash
# Pipe directly
./nfs_tls_test ... 2>&1 | scripts/analyze_nfs_results.py

# From a saved file
scripts/analyze_nfs_results.py results.txt

# Custom thresholds
scripts/analyze_nfs_results.py --fail-handshake-p99 200 results.txt
```

`AGENT.md` contains the full decision trees, threshold tables, and
failure diagnosis reference for AI-assisted analysis.

---

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text.
