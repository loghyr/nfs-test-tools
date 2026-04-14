<!-- SPDX-License-Identifier: Apache-2.0 -->

# Troubleshooting NFS over TLS (RFC 9289)

A practical guide to debugging RFC 9289 RPC-with-TLS for NFSv3 and
NFSv4.x.  Organised by where in the connection lifecycle the failure
happens, with pointers to `nfs_tls_test` for active probing.

This guide focuses on Linux (kernel TLS + `tlshd`).  FreeBSD has its
own `rpc.tlsclntd` / `rpc.tlsservd` daemons; the concepts transfer but
the daemon names and config files differ.

## Mental model

Think of NFS over TLS as four stacked layers:

```
  NFS application semantics  (mount, getattr, read/write, ...)
  --------------------------------------------------------------
  RPC transport              (XDR encoding, NULL probe, ...)
  --------------------------------------------------------------
  TLS                        (handshake via tlshd, kTLS data path)
  --------------------------------------------------------------
  TCP                        (port 2049 by default)
```

Every NFS-over-TLS failure isolates to one of those four layers.
The job of debugging is to identify which layer failed and look
**only at that layer's tools**.  This guide is structured to help
you do that.

The connection lifecycle has four phases (matching the phases
`nfs_tls_test` measures):

1. **TCP connect** to the server
2. **AUTH_TLS probe** -- a NULL RPC with the AUTH_TLS credential
   (flavor 7) asking the server to upgrade to TLS
3. **TLS handshake** -- ALPN protocol `sunrpc`, TLS 1.3 in modern
   deployments
4. **NFS NULL RPC** over the encrypted channel to confirm the
   data path works end-to-end

Failures land in exactly one of these phases.

## Pre-flight checks

Before debugging a connection, confirm the basics on both client and
server.

### Kernel version

NFS over TLS requires kernel TLS (kTLS) support and the SUNRPC TLS
glue.  TLS in NFS first appeared in Linux 6.5 but had several
critical fixes in later releases.

```
# Check kernel version
uname -r

# Check that the kernel was built with SUNRPC TLS support
grep CONFIG_SUNRPC_TLS /boot/config-$(uname -r)
# Want: CONFIG_SUNRPC_TLS=y

# Check that the tls module is loadable / loaded
lsmod | grep '^tls'
modprobe tls
```

Practical minimums:
- Linux **6.12+** is recommended for stable client behaviour
- RHEL 10 / Rocky 10 ship a kernel with reliable support
- Kernels older than 6.5 do not have NFS-over-TLS at all

### tlshd installed and running

The kernel does the kTLS data path, but the TLS *handshake* happens
in user space via `tlshd` (part of the `ktls-utils` package).

```
# Install
dnf install ktls-utils          # Fedora/RHEL/Rocky
apt install ktls-utils          # Debian/Ubuntu 23.04+

# Enable and start
systemctl enable --now tlshd
systemctl status tlshd
```

`tlshd` must be running on **both** client and server.  If a mount
fails with `mount.nfs: No such process`, the kernel asked `tlshd` to
do a handshake and nobody answered.

### Mount command actually requests TLS

```
mount -o vers=4.2,xprtsec=tls   server:/share /mnt/share
mount -o vers=4.2,xprtsec=mtls  server:/share /mnt/share
```

`xprtsec=tls` is server-authenticated.  `xprtsec=mtls` is mutual TLS
(client must present a cert).  Without one of these options, the
mount will use plaintext even if the server supports TLS.

To verify a live mount is actually using TLS:

```
mount | grep nfs
# Look for xprtsec=tls or xprtsec=mtls in the options

# Or check the proc state
cat /proc/self/mountinfo | grep nfs
```

If the option is missing on the active mount, TLS is not in use and
no amount of TLS debugging will help -- fix the mount line first.

## Phase-by-phase diagnosis

When something fails, identify the phase, then debug only that phase.
`nfs_tls_test` reports failures by phase in its `Error breakdown`
line:

```
Error breakdown: 0 tcp, 3 probe, 0 handshake, 0 rpc
```

The same phase decomposition applies to manual mount debugging.

### Phase 1: TCP connect

**Symptoms**

- `mount.nfs: Connection refused`
- `mount.nfs: Connection timed out`
- `nfs_tls_test`: `tcp` count > 0

**Causes and checks**

- Server not listening on port 2049: `ss -tnlp '( sport = :nfs )'`
- Firewall blocking the port: `nft list ruleset` /
  `iptables -L -n` / cloud security group
- Server NFS service down: `systemctl status nfs-server`
- Wrong server IP / hostname

Tools:
```
# Quick reachability check
nc -vz server 2049
```

A TCP failure has nothing to do with TLS.  Fix the network/service
first, then return to TLS debugging.

### Phase 2: AUTH_TLS probe

**Symptoms**

- TCP connects but the server immediately closes or returns garbage
- Mount falls back to plaintext (with `xprtsec=tls,fallback`)
- `nfs_tls_test`: `probe` count > 0

**Causes and checks**

The AUTH_TLS probe is the RFC 9289 mechanism: the client sends a
NULL RPC with credential flavor 7 (`AUTH_TLS`), and the server
responds with a verifier of `STARTTLS` to confirm it understands the
upgrade.  If the server isn't built with RFC 9289 support, it will
either:

1. Reject the unknown auth flavor
2. Treat it as a normal NULL RPC and return a normal NULL reply
3. Drop the connection

Either way, the client gives up before TLS.

Verification:
- Server must be a recent enough NFS implementation.  For Linux
  knfsd, `tls=y` in `/etc/nfs.conf` `[nfsd]` section.
- Run `nfs_tls_test --host server --verbose` to see the wire bytes
  of the probe and reply.

### Phase 3: TLS handshake

**Symptoms**

- TCP connects, AUTH_TLS probe succeeds, then TLS handshake fails
- `mount.nfs: access denied by server`
- Mount hangs and times out
- `nfs_tls_test`: `handshake` count > 0

This is **the most common failure mode** and almost always involves
certificates or ALPN.

**Increase tlshd verbosity**

`tlshd` logs to the system journal.  By default it logs almost
nothing.  Enable verbose logging in `/etc/tlshd.conf`:

```ini
[debug]
loglevel = 7
tls = 7
nl = 0

[authenticate]
```

`loglevel` is the daemon's own logging.  `tls` is the GnuTLS library
debug level (1-9; values above 3 add little).  `nl` is netlink
chatter, only useful when debugging `tlshd` itself.

Restart and watch:

```
systemctl restart tlshd
journalctl -u tlshd -f
```

For an even more direct view, stop the service and run `tlshd` in
the foreground in a terminal:

```
systemctl stop tlshd
tlshd -s
```

Foreground mode emits some log messages that the journal version
swallows.

A successful handshake ends with a message like:

```
tlshd[NNNN]: Session description: (TLS1.3)-(ECDHE-SECP384R1)-(RSA-PSS-RSAE-SHA384)-(AES-256-GCM)
tlshd[NNNN]: Handshake with '10.0.0.1' (10.0.0.1) succeeded
```

A failure typically looks like a chain of certificate errors:

```
tlshd[NNNN]: Certificate revoked.
tlshd[NNNN]: Certificate signer not found.
tlshd[NNNN]: Certificate signer not CA.
tlshd[NNNN]: Certificate uses insecure algorithm.
tlshd[NNNN]: Certificate not activated.
tlshd[NNNN]: Certificate expired.
tlshd[NNNN]: Certificate signature failure.
tlshd[NNNN]: Certificate owner unexpected.
tlshd[NNNN]: Certificate signer constraints failure.
tlshd[NNNN]: Certificate mismatch.
tlshd[NNNN]: Certificate purpose mismatch.
tlshd[NNNN]: Certificate has missing OCSP status.
tlshd[NNNN]: Certificate has unknown crit extensions.
```

`tlshd` prints all the possible failure modes from the GnuTLS
verification result -- the actual cause is whichever ones are
non-zero in the bitmask.  Skip to the certificate validation section
below.

**Don't forget ALPN**

RFC 9289 requires the TLS ALPN protocol name `sunrpc`.  If the
server's TLS stack does not advertise `sunrpc` in ALPN, the client
will reject the handshake.  This is often missed by general-purpose
TLS troubleshooting guides.  `nfs_tls_test --tls-info` reports the
negotiated ALPN; absence of `sunrpc` is the cause.

### Phase 4: NFS NULL RPC

**Symptoms**

- TLS handshake succeeds, then the connection closes or hangs
- Mount succeeds but immediately fails with EIO
- `nfs_tls_test`: `rpc` count > 0

This means the encrypted channel is up but the NFS stack on the
server is not responding correctly over it.  Possible causes:

- Server NFS configuration error (TLS-required export, no flavours
  permitted)
- Post-handshake certificate verification failure (some servers
  validate peer identity *after* the handshake completes and then
  drop the socket)
- Kernel TLS bug (RX/TX rekey failures, see `/proc/net/tls_stat`
  below)

Check the server's NFS logs and `/proc/net/tls_stat` on both ends.

## Logging and tracing

### Server-side NFS daemon logs

For Linux knfsd, NFS daemon errors land in the kernel ring buffer
and the system journal:

```
dmesg --follow
journalctl -k -f
journalctl -u nfs-server -f
```

For user-space NFS servers, consult the server's own logging
controls.  Most user-space NFS servers have a verbose / debug mode
specifically for TLS that emits cipher suite, ALPN, and certificate
chain details.

### tlshd journal (both ends)

```
journalctl -u tlshd -f
journalctl -t tlshd --since "10 minutes ago"
```

Use `-t tlshd` rather than `-u tlshd` if you also want to see
foreground (`tlshd -s`) output.

### GnuTLS library debug

Beyond the `tlshd.conf` `[debug]` section, you can drive GnuTLS
directly from the environment for finer control:

```
GNUTLS_DEBUG_LEVEL=9 tlshd -s
```

This produces voluminous output -- only useful for diagnosing the
TLS library itself.

### Kernel SUNRPC TLS tracepoints

The kernel exposes per-event tracepoints for SUNRPC TLS state
transitions.  These are the fastest way to see whether the kernel
even attempted to invoke `tlshd`.

```
# Enable all SUNRPC TLS tracepoints
echo 1 | tee /sys/kernel/tracing/events/sunrpc/*tls*/enable

# (optional) record process names with each event
echo 1 > /sys/kernel/tracing/options/record-cmd

# Read live
cat /sys/kernel/tracing/trace_pipe

# Read accumulated buffer
cat /sys/kernel/tracing/trace

# Disable when done
echo 0 | tee /sys/kernel/tracing/events/sunrpc/*tls*/enable
```

Notable tracepoints:

- `rpc_tls_unavailable` -- the server doesn't support STARTTLS
- `rpc_tls_not_conf` -- TLS is required but not configured
- `rpc_tls_handshake_complete` -- the handshake succeeded

If your client is configured for TLS but `rpc_tls_handshake_complete`
never fires, the failure is upstream in the handshake flow.

### Kernel TLS handshake tracepoints

The generic kTLS layer also exposes tracepoints under
`/sys/kernel/debug/tracing/events/handshake/`:

```
echo 1 > /sys/kernel/debug/tracing/events/handshake/tls_contenttype/enable
cat /sys/kernel/debug/tracing/trace_pipe > /tmp/handshake.trace
```

You will typically see ~250 `HANDSHAKE` content-type messages per
TLS handshake.  Two simultaneous sessions (one per direction in
mutual TLS) yield ~500 messages total.

These are most useful for confirming whether handshakes are
*starting* on the kernel side, regardless of whether they complete.

### /proc/net/tls_stat counters

The kernel TLS layer maintains namespace-scoped counters in
`/proc/net/tls_stat`.  Snapshot before and after a test run to see
what changed:

```
cat /proc/net/tls_stat
```

Interesting fields:

| Counter | Meaning |
|---|---|
| `TlsCurrTxSw`, `TlsCurrRxSw` | Active TX/RX sessions handled in software |
| `TlsCurrTxDevice`, `TlsCurrRxDevice` | Active sessions offloaded to NIC |
| `TlsTxSw`, `TlsRxSw` | Cumulative software sessions opened |
| `TlsDecryptError` | A record failed authentication tag verification (corruption, MITM, or kernel bug) |
| `TlsDecryptRetry` | Records re-decrypted due to `TLS_RX_EXPECT_NO_PAD` mis-prediction |
| `TlsRxNoPadViolation` | Data records re-decrypted (subset of above) |
| `TlsTxRekeyOk`, `TlsRxRekeyOk` | Successful in-session rekeys |
| `TlsTxRekeyError`, `TlsRxRekeyError` | Failed rekeys |
| `TlsRxRekeyReceived` | Received `KeyUpdate` messages requiring user-space to provide a new RX key |

A passing functional test that increments `TlsDecryptError` is a
real failure that latency-only monitoring will miss.

### NFS protocol stats

```
nfsstat -c          # client side
nfsstat -s          # server side
cat /proc/net/rpc/nfs
cat /proc/net/rpc/nfsd
```

Useful for confirming that NFS operations are actually flowing over
the encrypted transport.  An NFS-over-TLS mount should still
increment the same counters as a plaintext mount.

### RPC debug bits

The classic kernel RPC debug surface still works:

```
sysctl -w sunrpc.rpc_debug=1024
dmesg --follow
# Disable when done
sysctl -w sunrpc.rpc_debug=0
```

The 1024 bit (`RPCDBG_TRANS`) covers transport-layer debugging
including the TLS upgrade path.  Other bits are documented in
`include/linux/sunrpc/debug.h` in the kernel source.

## Certificate and PKI validation

Most TLS handshake failures are certificate problems.  The
certificate path has more independent failure modes than any other
part of the stack.

### Inspect a certificate

```
openssl x509 -in /path/to/cert.pem -text -noout
```

Things to check:

- **Validity period:** `Not Before` is in the past, `Not After` is
  in the future
- **Subject:** matches what the server identifies itself as
- **Issuer:** matches a CA that the peer trusts
- **Subject Alternative Name (SAN):** must include every IP / DNS
  name a client might use to reach the server.  This is the most
  frequent cause of "certificate mismatch" errors.
- **Key usage / EKU:** must permit `serverAuth` (and `clientAuth`
  for mutual TLS)

```
# Just the SAN
openssl x509 -noout -ext subjectAltName -in /path/to/cert.pem

# Verify the cert against a CA
openssl verify -CAfile /path/to/ca.pem /path/to/cert.pem
```

### Verify the cert/key pair matches

```
# These should produce the same SHA256
openssl x509 -in cert.pem -noout -modulus | openssl sha256
openssl rsa  -in key.pem  -noout -modulus | openssl sha256
```

### Trust store membership

The peer must have your CA in its trust store:

```
# RHEL/Fedora/Rocky
cp ca.pem /etc/pki/ca-trust/source/anchors/
update-ca-trust
trust list | grep -A2 'YourCAName'

# Debian/Ubuntu
cp ca.pem /usr/local/share/ca-certificates/yourca.crt
update-ca-certificates
```

### Standalone TLS smoke test with socat

If you suspect the certificates themselves are broken, take NFS out
of the loop entirely.  Run a TLS echo server with `socat` using the
same cert files NFS would use, and connect from the peer:

```
# On the would-be server (pick any free port):
socat openssl-listen:4433,reuseaddr,\
certificate=/path/to/cert.pem,\
key=/path/to/key.pem,\
cafile=/path/to/ca.pem,\
verify=2,\
openssl-min-proto-version=TLS1.3 STDIO

# On the would-be client:
socat -d stdio openssl-connect:server:4433,\
certificate=/path/to/cert.pem,\
key=/path/to/key.pem,\
cafile=/path/to/ca.pem,\
verify=1,\
openssl-min-proto-version=TLS1.3
```

This tests certificate trust, hostname/IP matching, cipher
negotiation, and TLS 1.3 support without ever invoking RPC.  If
this fails, NFS will too.  If this works but NFS doesn't, the
problem is in the NFS or `tlshd` layer.

To check whether the CA is in the system trust store, omit
`cafile=` from both sides.  If the connection still works, the CA
is trusted.

### openssl s_server / s_client

A heavier alternative to `socat`:

```
# Server
openssl s_server -port 4433 \
  -cert /path/to/cert.pem -key /path/to/key.pem \
  -CAfile /path/to/ca.pem \
  -msg -Verify 2 -status \
  -verify_hostname server.example.com \
  -tls1_3

# Client
openssl s_client -connect server:4433 \
  -cert /path/to/cert.pem -key /path/to/key.pem \
  -CAfile /path/to/ca.pem \
  -msg -tls1_3 -status
```

Note that `openssl s_client -connect server:2049` does **not** test
NFS-over-TLS, because RFC 9289 uses STARTTLS (the AUTH_TLS probe
mechanism), not raw TLS on the NFS port.  An `s_client` to port 2049
will hang or get a garbled response.  Use `nfs_tls_test` for that.

## Decrypted packet capture

Once TLS is in the picture, `tcpdump` and `tshark` will only show
encrypted blobs.  To get a decrypted capture, you need to log the
TLS session keys to a file and import that into Wireshark.

### Step 1: stop tlshd as a service

```
systemctl stop tlshd
```

### Step 2: create the keylog file

```
touch /tmp/keylog.txt
chmod a+w /tmp/keylog.txt
```

The file must be writable by the user running `tlshd` (root in the
default service config).

### Step 3: run tlshd manually with SSLKEYLOGFILE

```
SSLKEYLOGFILE=/tmp/keylog.txt tlshd -s
```

Alternatively, edit the systemd unit (`systemctl edit tlshd.service`)
to set:

```ini
[Service]
Environment="SSLKEYLOGFILE=/tmp/keylog.txt"
```

and `systemctl restart tlshd`.

### Step 4: capture packets

```
tshark -i ens0 -w /tmp/tls.pcap host server and tcp port 2049
```

Or with `tcpdump`:

```
tcpdump -i ens0 -w /tmp/tls.pcap host server and tcp port 2049
```

### Step 5: trigger the connection

```
mount -o vers=4.2,xprtsec=mtls server:/share /mnt/share
```

A successful mount typically captures around 50 packets.

### Step 6: decrypt in Wireshark

`File -> Preferences -> Protocols -> TLS` and set
`(Pre)-Master-Secret log filename` to `/tmp/keylog.txt`.  Open the
pcap.  Wireshark may need to be told that port 2049 carries TLS;
in the same dialog, add `2049,tls` to the TLS port list.

Or from the command line:

```
tshark -r /tmp/tls.pcap \
  -o "tls.keylog_file:/tmp/keylog.txt" \
  -d "tcp.port==2049,tls"
```

You should now see `Client Hello`, `Server Hello`, `Certificate`,
`Finished`, then the decrypted RPC and NFS layers.  Without the
keylog, all the post-handshake packets show as
`TLSv1.3 Application Data` and that's it.

### Server-side keylog

On the client side, `tlshd`'s `SSLKEYLOGFILE` covers everything the
client does.  If you need to debug a server-side issue and the
server is also using `tlshd` for handshakes, the same recipe works
on the server.

If the server uses its own TLS implementation (some user-space NFS
servers do), check whether it has a keylog feature -- look for
`tls_keylog`, `keylog_file`, or `SSL_CTX_set_keylog_callback` in
its docs and source.

## Common errors and what they mean

### `mount.nfs: an incorrect mount option was specified`

You used `xprtsec=mtls` (or `tls`) on a system whose `mount.nfs`
doesn't recognise the option.  Upgrade `nfs-utils` to a version
that supports RFC 9289 mount options, or upgrade your distro.

### `mount.nfs: No such process`

`tlshd` is not running.  The kernel asked user space to do a TLS
handshake and got no response.

```
systemctl enable --now tlshd
systemctl status tlshd
```

### `mount.nfs: Connection refused`

The server is not listening on port 2049, or the NFS server process
is not running.  Not a TLS problem.

### `mount.nfs: Operation not permitted`

The server received the connection but rejected it before TLS
completed, often because of stale state on the client or because
the server expects a specific transport security mode the client
isn't providing.  Check the server logs for the corresponding
rejection.

### `mount.nfs: access denied by server while mounting`

This is almost always certificate validation, and it can fail in
either direction (server rejecting client cert, or client rejecting
server cert).  Look in the `tlshd` journal on both ends for the
GnuTLS error chain printed in the previous section.  Common root
causes:

- Self-signed cert not in the peer's trust store
- Hostname / IP not in the cert's SAN
- Cert expired or not yet valid
- CA chain incomplete (intermediate CA missing)
- For mutual TLS: server is configured for `mtls` but client did
  not present a cert at all

### Mount hangs forever

Usually means the AUTH_TLS probe was sent and the server never
replied, or the TLS handshake started and stalled.  Run
`nfs_tls_test --host server --verbose` -- it will time out
quickly and tell you which phase stalled.

### Mount succeeds but every operation returns EIO

The handshake completed but post-handshake validation failed.  Some
servers do certificate validation **after** the handshake completes
and then drop the socket.  The mount appears successful but the
first real operation fails.  Server-side logs are the only way to
see what went wrong.

### Intermittent NFS4ERR_DELAY or timeouts

TLS adds latency.  Under load, kernel TLS work queues can back up
and surface as protocol-level delays.  Watch:

```
watch -n1 cat /proc/net/tls_stat
```

If `TlsDecryptRetry` or rekey error counters are climbing, the data
path is unhealthy.  If the counters are quiet but you see
`NFS4ERR_DELAY` storms, look for layout recall or session-slot
exhaustion in NFS-layer logs.

## Active probing with nfs_tls_test

When manual debugging gets stuck, the `nfs_tls_test` tool in this
repo will tell you exactly which phase fails and how long each
phase takes.

### Quickest possible smoke test

```
./nfs_tls_test --host server
```

Returns immediately with an `Error breakdown` line.  All zeros means
TLS works end-to-end.  Non-zero in any phase tells you which layer
to debug.

### With certificate verification

```
./nfs_tls_test --host server \
  --ca-cert /path/to/ca.pem \
  --tls-info
```

`--tls-info` prints the negotiated TLS version, cipher, ALPN, and
session reuse rate.  Confirm `sunrpc` ALPN is being used.

### Mutual TLS

```
./nfs_tls_test --host server \
  --ca-cert /path/to/ca.pem \
  --cert /path/to/client.pem \
  --key /path/to/client.key
```

### Stress test for race conditions

```
./nfs_tls_test --host server \
  --threads 8 --duration 60 \
  --tls-info --histogram
```

Concurrent connections expose handshake-time races, accept-queue
overflows, session-cache contention, and rekey errors that
single-connection tests miss.

### NFSv3-only servers

NFSv3 implementations of RFC 9289 may reject the post-handshake
NULL RPC because the tool sends it as NFSv4.  Skip phase 4:

```
./nfs_tls_test --host server --no-null
```

This still verifies TCP, AUTH_TLS probe, and TLS handshake.

### Reading the output

The `analyze_nfs_results.py` script in `scripts/` parses
`nfs_tls_test` output and emits a structured PASS/FAIL/WARN
verdict:

```
./nfs_tls_test --host server --tls-info 2>&1 | scripts/analyze_nfs_results.py
echo $?    # 0=PASS, 1=FAIL, 2=WARN
```

See `AGENT.md` for the full decision tree, threshold table, and
phase diagnosis mapping.

## A debugging checklist

When everything is broken and you don't know where to start:

1. **Pre-flight:** kernel ≥ 6.12, `tlshd` running on both ends, mount
   command actually contains `xprtsec=tls` or `xprtsec=mtls`.
   Run `nfs_tls_test --diagnose` to check most of this in one shot.
2. **Reachability:** `nc -vz server 2049` succeeds.
3. **Cert sanity:** `nfs_cert_info --cert ... --key ... --ca ...` to
   validate the cert files locally without involving NFS at all.
4. **Standalone TLS:** `socat` smoke test using the same cert files.
   If this fails, NFS is irrelevant -- fix the certs.
5. **Active probe:** `nfs_tls_test --host server --tls-info
   --check-san "IP:...,DNS:..." --snapshot-stats`.  Read the
   `Error breakdown`, `tls-info`, and kTLS counter delta output.
6. **tlshd journal:** `journalctl -u tlshd -f` on both ends with
   `loglevel=7`, `tls=7` in `/etc/tlshd.conf`.  Trigger the failing
   mount.  Read the GnuTLS error chain.
7. **Kernel tracepoints:** enable
   `/sys/kernel/tracing/events/sunrpc/*tls*/enable` and watch
   `trace_pipe` to confirm the kernel is even attempting the
   handshake.
8. **Decrypt the wire:** `nfs_tls_test --host server
   --keylog /tmp/keylog.txt` (or `SSLKEYLOGFILE` for `tlshd`) +
   `tshark` + Wireshark to see the actual protocol exchange
   post-handshake.
9. **kTLS counters:** `cat /proc/net/tls_stat` before and after, or
   let `nfs_tls_test --snapshot-stats` do it for you.  Look for
   `TlsDecryptError` and rekey errors.

If you get to step 9 and still don't know what's wrong, the failure
is probably in the NFS server's TLS integration (server-side bug)
or in a kernel TLS edge case.  Capture everything and file an
upstream bug.

## nfs_tls_test error reference

When `nfs_tls_test` detects a failure it prints a line of the form:

```
[ERROR <SYMBOL>]  (<count> failure(s))
    <description>
    Fix: <suggestion>
    See: TROUBLESHOOTING.md#<anchor>
```

The `<SYMBOL>` and `<anchor>` are stable identifiers from the
canonical taxonomy in `src/tls_error.h` and can be matched on by CI
tooling.  The full table is available via:

```
./nfs_tls_test --print-error-table
```

The exit status is the symbolic code's numeric value (e.g. 41 for
`CERT_EXPIRED`), or `90` (`MIXED`) if more than one failure class
occurred in the same run, or `0` on success.  Codes are spaced (10,
11, 12, ... 20, 21, ... 99) so the taxonomy can grow without
renumbering.

The subsections below collect the more common nfs_tls_test failure
modes with the same anchor names that appear in the runtime output.
Many of them cross-reference earlier sections in this document.

### kernel_too_old

The Linux kernel on the client (or server) is below the NFS-over-TLS
support floor.  See `### Kernel version` above for the exact required
versions and how to verify with `uname -r`.

### no_sunrpc_tls_config

Kernel was built without `CONFIG_SUNRPC_TLS`.  Verify with:

```
zgrep CONFIG_SUNRPC_TLS /proc/config.gz   # if exposed
grep CONFIG_SUNRPC_TLS /boot/config-$(uname -r)
```

The fix is to use a kernel built with `CONFIG_SUNRPC_TLS=y` or `=m`.
Distros that ship NFS-over-TLS support enable this by default.

### no_tls_module

Kernel TLS module is not loaded.  Run `modprobe tls` and verify with
`lsmod | grep ^tls`.  If the module load itself fails, the kernel
was built without `CONFIG_TLS=y` or `=m`.

### no_tlshd

`tlshd` binary not installed.  Install the `ktls-utils` package
(distro-specific name varies).  See `### tlshd installed and running`
above.

### tlshd_not_running

`tlshd` is installed but not running.  See `### tlshd installed and
running` above.

### openssl_too_old

The OpenSSL library `nfs_tls_test` was linked against is too old to
speak TLS 1.3.  Rebuild against OpenSSL >= 1.1.1.  Note this is the
*client tool's* OpenSSL, not the kernel's.

### tcp_refused

TCP-level rejection by the server before any TLS work happens.  See
`### Phase 1: TCP connect` above for the full debugging steps.
Quick check: `nc -vz server 2049`.

### tcp_timeout

TCP `connect()` timed out.  Almost always firewall, network MTU
issues, or the server is unreachable.  See `### Phase 1: TCP connect`.

### tcp_host_not_found

DNS resolution for `--host` failed.  Verify the spelling, then
`getent hosts <name>` and `dig +short <name>` to isolate the
resolver.

### probe_rejected

The server received the AUTH_TLS NULL probe and rejected it
explicitly with an RPC error.  See `### Phase 2: AUTH_TLS probe`
above.  The most common cause is that the server's NFS daemon does
not implement RFC 9289 STARTTLS at all.

### probe_malformed_reply

Server responded to the probe but the reply was not parseable as a
well-formed RPC reply.  This is a server bug -- the server's
RFC 9289 implementation has a wire-format issue.  Capture and file
an upstream bug.

### probe_no_starttls

The server's RPC reply indicated it does not support STARTTLS upgrade.
Enable TLS in the server's NFS configuration (commonly `tls=y` in
`/etc/nfs.conf` for Linux nfs-server, or the equivalent for the
server vendor).

### tls_enabled_unexpectedly

The server answered the AUTH_TLS NULL probe with `MSG_ACCEPTED`, but
the tester told us (via `--expect-no-tls`) that the server is
supposed to have TLS disabled.  This is a **server-side RFC 9289
violation**: per §4.1, a server without TLS enabled must answer the
probe with `MSG_DENIED` (rejection reason `AUTH_ERROR`, `au_stat =
AUTH_REJECTEDCRED`), not `MSG_ACCEPTED`.

A concrete instance: a Hammerspace Anvil running with
`tls_peer_mode = 0` in `/pd/fs/protod.conf` (TLS disabled globally)
that still answers the AUTH_TLS probe with `MSG_ACCEPTED`.  The
client then proceeds to the handshake, which may or may not succeed
depending on whether the server has TLS certs loaded at all -- but
the *probe answer itself* has lied, and the bug is in the probe
handler, not in the handshake path.

To reproduce:

```
nfs_tls_test --host <server-with-tls-off> --expect-no-tls
```

Exit code `33` (`TLS_ENABLED_UNEXPECTEDLY`) means the server
answered `MSG_ACCEPTED`.  Exit code `0` means the server correctly
answered `MSG_DENIED`.  Any other exit code means the probe itself
failed (TCP refused, malformed reply, etc.) and the test is
inconclusive.

Fix: the server's RPC NULL handler for AUTH_TLS must check whether
TLS is enabled on the listener before replying `MSG_ACCEPTED`.  When
TLS is off, reply with an `MSG_DENIED` containing rejection reason
`AUTH_ERROR` and `au_stat = AUTH_REJECTEDCRED`.

### handshake_failed

Generic catch-all for `SSL_connect()` failure with no more specific
classification.  The most actionable next step is to capture the
keylog and decrypt the handshake in Wireshark:

```
./nfs_tls_test --host server --keylog /tmp/keylog.txt --iterations 1
```

See `## Decrypted packet capture` above for the full procedure.

### cert_expired

Server certificate has expired.  Run `nfs_cert_info --cert
server.crt` (or `openssl x509 -in server.crt -noout -dates`) to see
`notBefore` / `notAfter`.  Renew the cert.

### cert_not_yet_valid

The server certificate's `notBefore` is in the future.  Almost
always a client/server clock skew problem.  Check NTP on both ends:

```
chronyc tracking
timedatectl status
```

### cert_untrusted

The client did not trust the server's certificate chain.  Either
add the issuing CA to the client trust store, or pass it explicitly
via `--ca-cert`.  See `### Trust store membership` above.

### cert_hostname

Server presented a certificate but the CN/SAN did not match the
hostname or IP that `--host` resolved to.  Run:

```
./nfs_cert_info --cert server.crt
```

and inspect the SAN list.  Reissue the cert with the correct
DNS/IP entries.

### cert_revoked

The server certificate has been revoked.  Issue a new certificate.

### cert_key_mismatch

The server's certificate and private key do not match -- this is a
server-side configuration error.  See `### Verify the cert/key pair
matches` above.

### alpn_mismatch

Per RFC 9289 §4, the server must negotiate ALPN protocol `sunrpc`.
If your client sees this error, the server's TLS stack did not
advertise `sunrpc` in its ALPN list.  Confirm the server software
version supports RFC 9289, and that any TLS profile / cipher policy
is not stripping ALPN.  Use `--require-alpn sunrpc` to make this a
hard fail.

### tls_version_too_low

The negotiated TLS version is below 1.3.  RFC 9289 requires
TLS 1.3.  Configure the server to support and prefer TLS 1.3.  Use
`--require-tls13` to make this a hard fail.

### san_missing

A specific SAN entry that you required via `--check-san` is not
present in the server's certificate.  The error message names the
missing entry.  Reissue the cert.

### no_peer_cert

The server completed (or attempted) the handshake without
presenting any certificate at all.  The server has TLS misconfigured
or has no cert loaded.  Check the server's TLS config and logs.

### rpc_failed

The TLS handshake succeeded but the post-handshake NFS NULL RPC was
rejected.  See `### Phase 4: NFS NULL RPC` above.  For NFSv3-only
servers, pass `--no-null` to skip this phase.

### rpc_timeout

The NULL RPC after the TLS handshake never completed.  Server NFS
stack is hung or overloaded.  Check server logs and load.

### ktls_decrypt_error

The kernel TLS layer logged a `TlsDecryptError` during the run (via
`--snapshot-stats`).  Indicates wire corruption, MITM, or a kernel
TLS bug.  See `### /proc/net/tls_stat counters` above.

### ktls_rekey_error

`TlsTxRekeyError` or `TlsRxRekeyError` was incremented during the
run.  TLS 1.3 key update failed; check kernel version and consider
filing a kernel bug.

### ktls_no_pad_violation

`TlsRxNoPadViolation` was incremented.  This is a `TLS_RX_EXPECT_NO_PAD`
mis-prediction inside the kernel TLS layer; usually benign.

### mixed

More than one distinct failure class occurred in the same run.
Inspect the per-phase Error breakdown line and the individual
`[ERROR ...]` blocks above it for details.

### internal

A tool internal error (out of memory, bad command-line argument).
Not a TLS or server problem.  File a bug against `nfs-test-tools`.

## NFS over Kerberos

Kerberized NFS (sec=krb5, krb5i, krb5p) is three systems glued
together: Kerberos itself (auth), RPCSEC_GSS (RFC 2203), and NFSv4
identity mapping.  Failures in any layer surface as generic NFS
errors (`EIO`, `permission denied`, `nobody:nobody`), and the
documentation is famously scattered.  This section gathers the
known failure modes that `nfs_krb5_test` can detect, with stable
anchor names matching the symbolic codes the runtime emitter
prints.

### Mental model

```
   user / nfs.gssd ──┐
                    │ kinit, klist, keytab
                    ▼
          ┌─────────────────┐         ┌────────────┐
          │   libkrb5       │ ◀────── │ krb5.conf  │
          │  (this process) │         │ keytab     │
          └────────┬────────┘         └────────────┘
                   │ TGT  / service ticket
                   ▼
          ┌─────────────────┐
          │     KDC         │
          └────────┬────────┘
                   │ ticket
                   ▼
          ┌─────────────────┐
          │     GSS-API     │  init_sec_context, get_mic, wrap
          └────────┬────────┘
                   │ context handle, tokens
                   ▼
          ┌─────────────────┐
          │  RPCSEC_GSS     │  RFC 2203: cred + verifier wire format
          │  (NFS / kernel) │  per-call seq_num, replay window
          └────────┬────────┘
                   │ NFS ops (open, read, lookup, secinfo)
                   ▼
          ┌─────────────────┐
          │ nfsidmap        │  uid <-> name@DOMAIN mapping
          └─────────────────┘
```

The four layers correspond directly to the phases the runtime tool
classifies failures into: PRE_FLIGHT (config / keytab / hostname),
KERBEROS (libkrb5 talking to the KDC), GSS (the GSS-API abstraction
above libkrb5), RPCSEC_GSS (the RFC 2203 wire layer), and IDMAP
(post-auth identity mapping).

### KRB5_TRACE -- the most useful single tool

When a krb5 failure isn't obvious, set `KRB5_TRACE` to a file path
and re-run.  libkrb5 will write every step it takes to that file:
which keytab entry it picked, which KDC it contacted, which enctype
it negotiated, which ticket it cached.

```
KRB5_TRACE=/dev/stderr nfs_krb5_test --host server --verbose

# or via the tool's flag:
nfs_krb5_test --host server --krb5-trace /tmp/krb5.log
```

**Critical scope limitation:** `KRB5_TRACE` only captures libkrb5
calls made *inside the process where it is set*.  Mount-time NFS
failures happen inside `rpc.gssd` (or `gssproxy`), not inside
`mount.nfs` or this tool.  When the failure is on the kernel-side
mount path you also need:

```
# kernel rpcdebug:
rpcdebug -m rpc -s auth

# rpc-gssd journal:
journalctl -u rpc-gssd -f

# gssproxy journal (modern distros):
journalctl -u gssproxy -f
```

### Active probing with nfs_krb5_test

```
# Pre-flight: validate the local krb5 environment without touching
# the network at all.
./nfs_krb5_test --diagnose

# Single-shot connectivity check (sec=krb5, auth only):
./nfs_krb5_test --host server

# Integrity (krb5i): proves the server can verify a MIC over the
# RPC arguments, not just the call header.
./nfs_krb5_test --host server --sec krb5i

# Privacy (krb5p): proves the server can decrypt wrapped arguments.
./nfs_krb5_test --host server --sec krb5p

# Stress mode: 10000 calls on a single context, churning the seq_num
# against the server's RPCSEC_GSS replay window.  Aggregates per-
# symbolic-code failure counts and reports them at the end.
./nfs_krb5_test --host server --sec krb5p --iterations 10000 --stress

# With libkrb5 trace capture for in-process failures:
./nfs_krb5_test --host server --krb5-trace /tmp/krb5.log --verbose

# Print the full krb5 error taxonomy as a markdown table:
./nfs_krb5_test --print-error-table
```

### nfs_krb5_test error reference

When `nfs_krb5_test` detects a failure it prints a line of the form:

```
[ERROR <SYMBOL>]  (<context>)
    <description>
    Fix: <suggestion>
    See: TROUBLESHOOTING.md#<anchor>
```

The `<SYMBOL>` and `<anchor>` are stable identifiers from the
canonical taxonomy in `src/krb5_error.h`.  The exit status is the
symbolic code's numeric value (100..199 for krb5-domain failures,
or `250` (`MIXED`) if more than one class occurred in the same run).

The subsections below match the anchors emitted at runtime.  Many
of them describe failures that the tool can also detect during
pre-flight via `--diagnose`.

#### Pre-flight (local environment)

##### no_krb5_conf

`/etc/krb5.conf` is missing or unreadable.  libkrb5 cannot determine
the realm, KDC location, or default options.

```
ls -lZ /etc/krb5.conf      # check existence and SELinux label
cat /etc/krb5.conf | head  # confirm it's a real config, not empty
```

Fix: install or restore the file, or set `KRB5_CONFIG` to point at
an alternate location.

##### krb5_conf_parse

`/etc/krb5.conf` exists but libkrb5 fails to parse it.  Most often
a missing closing `}` after a stanza, or a syntax error in
`[realms]`.

```
klist 2>&1 | head            # libkrb5 prints the parser error
```

Fix the line libkrb5 names.

##### no_default_realm

`[libdefaults]` has no `default_realm` set.  Many tools (including
`mount.nfs`) need this to construct service principal names.

```
[libdefaults]
    default_realm = EXAMPLE.COM
```

##### no_keytab_file

`/etc/krb5.keytab` does not exist.  Without it, the host has no
machine credential and `rpc.gssd -n` can't acquire one for the
mount path.

Generate or restore via `kadmin ktadd nfs/<host>@REALM` (or your
distro's equivalent), then verify with `klist -k`.

##### keytab_not_readable

The keytab exists but the current uid cannot read it.  Two common
causes:

1. **Unix permissions.** Default is mode `0600` owned by `root`.
   The tool runs as a non-root user.
2. **SELinux file context.** The keytab must be labeled
   `krb5_keytab_t`.  Check with `ls -Z /etc/krb5.keytab`; relabel
   via `restorecon /etc/krb5.keytab` if needed.

##### no_nfs_principal

The keytab is readable but does not contain an `nfs/<host>@REALM`
service principal.  Without one, the host cannot accept inbound
GSS contexts and (depending on configuration) cannot initiate
outbound ones either.

```
klist -k /etc/krb5.keytab | grep nfs/
```

If the list is empty, add the principal via your KDC's admin tool
and re-export the keytab.

##### no_gssproxy_or_gssd

Neither `gssproxy` nor `rpc.gssd` is running.  One of them must be
present to broker GSS context establishment for the kernel NFS
client.

```
systemctl status gssproxy   # modern distros
systemctl status rpc-gssd   # legacy
systemctl enable --now gssproxy
```

Modern Fedora / RHEL 8+ defaults to `gssproxy`; older systems use
`rpc.gssd`.  Some distros run both, which is fine but redundant.

##### no_nfsidmap

`nfsidmap` is not installed.  NFSv4 cannot map uids to names without
it.  Symptom: every file appears as `nobody:nobody`.

Install `nfs-utils` or `libnfsidmap` per your distro's packaging.

##### hostname_not_fqdn

The local hostname is a short name without a domain part (e.g.
`client` instead of `client.example.com`).  Kerberos service
principals are derived from canonical FQDNs; a short hostname
breaks principal-form matching at runtime.

```
hostnamectl set-hostname client.example.com
```

##### rdns_mismatch

Forward and reverse DNS for the local hostname disagree.  Kerberos
authenticates by canonical name, and many KDC / NFS-server
combinations rely on the reverse PTR matching the forward A/AAAA
record.

Either fix DNS so that they agree, or set `rdns = false` in
`[libdefaults]` (with the caveat that some KDCs reject AS_REQs from
clients with broken reverse DNS regardless).

#### Kerberos / libkrb5

##### clock_skew

Clock skew between the client and the KDC exceeds the allowed
window (default 5 minutes).  This is *the* number-one cause of
"works on my workstation, fails on the server" Kerberos issues.

```
chronyc tracking
chronyc sources
timedatectl status
```

Both ends must be within the skew window.  Note: the *server's*
clock must also agree with the KDC's; a skew between the NFS
server and the KDC will surface as failures on the client even if
the client's clock is fine.

##### kdc_unreachable

libkrb5 could not reach any KDC for the realm.  Causes:

- Wrong `kdc =` entries in `/etc/krb5.conf [realms]`
- DNS SRV records (`_kerberos._tcp.REALM`) missing or wrong, when
  using `dns_lookup_kdc = true`
- Firewall blocking outbound port 88 (TCP and/or UDP)
- KDC service down

```
KRB5_TRACE=/dev/stderr kinit user@REALM
```

The trace shows which KDCs are tried and the failure for each.

##### no_tgt

No Kerberos TGT in the user's credential cache.  For a user-initiated
mount this means the user hasn't run `kinit`.  For a machine-cred
path (mount triggered by `rpc.gssd -n` or `gssproxy`) it means the
machine couldn't obtain a TGT from its keytab -- check the daemon
logs.

##### tgt_expired

The TGT has expired.  Kerberos default lifetime is 10 hours; long-
lived NFS mounts need automatic renewal (sssd, k5start, gssproxy
with appropriate config).  Run `kinit -R` to renew or `kinit
user@REALM` to re-acquire.

##### tgt_not_yet_valid

The TGT's `starttime` is in the future.  Almost always a clock skew
on the KDC at issue time -- check NTP on the KDC, not on the client.

##### keytab_no_principal

`gss_init_sec_context` (or `gss_acquire_cred`) needed a principal
that wasn't in the keytab.  Distinct from `no_nfs_principal` in
that this is detected at runtime against a specific principal name
the runtime constructed (which may differ from `nfs/<host>` in
unusual configurations).

##### bad_enctype

KDC returned `KRB5KDC_ERR_ETYPE_NOSUPP`: no enctype the KDC supports
overlaps with what the keytab carries.  Most often after a FIPS
toggle or a `permitted_enctypes` change.

```
klist -ket /etc/krb5.keytab    # see the keytab's enctypes
```

Add `aes256-cts-hmac-sha1-96` (or `aes128-cts-hmac-sha1-96`) to
`permitted_enctypes` in krb5.conf and re-key the principal in the
KDC database.

##### enctype_negotiation

Three-way intersection of (keytab enctypes, krb5.conf
`permitted_enctypes`, KDC's allowed enctypes for this principal) is
empty.  Distinct from `bad_enctype` in that the keytab and the KDC
each support enctypes individually but they don't overlap.

Inspect all three sets and ensure at least one common enctype.

##### principal_unknown

KDC returned `KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN`: the service
principal does not exist in the KDC database.  Either add it via
`kadmin`, or fix the SPN form the client requested.

##### preauth_failed

Pre-authentication failed.  Wrong password, locked account, or a
PA-DATA mismatch.  Check the KDC logs for the specific reason.

##### bad_kvno

`KRB5KRB_AP_ERR_BADKEYVER`: the keytab and the KDC database disagree
on the principal's key version.  Caused by re-keying the principal
on one side (KDC or keytab) without propagating to the other.  Fix
by re-keying via `kadmin ktadd` so both sides see the same kvno.

##### bad_integrity

`KRB5KRB_AP_ERR_BAD_INTEGRITY`: ticket decryption failed.  Common
causes:

- Stale keytab on the server (re-keyed principal not re-exported)
- Cross-realm trust chain broken at one hop
- Clock skew large enough to invalidate the ticket key derivation

A `KRB5_TRACE` capture on both ends usually identifies which.

##### principal_form

Principal name form mismatch -- e.g. `nfs/host@REALM` vs
`nfs/host.fqdn@REALM`.  Distinct from `rdns_mismatch` (which is
about DNS round-trips).  Use the FQDN form everywhere and align
with what the KDC has registered.

##### not_us

`KRB5_AP_ERR_NOT_US`: the server thinks the ticket presented is for
a different principal.  Almost always caused by hostname
canonicalization disagreeing between the client and server (rdns,
`dns_canonicalize_hostname`, the hostname the kernel knows itself
by vs the one DNS resolves it to).

##### bad_realm

A cross-realm path is missing or broken.  Verify `[domain_realm]`
mapping in krb5.conf, the trust direction in the KDC database,
and `[capaths]` if you use it.

#### GSS-API layer

##### gss_bad_name

`gss_import_name` returned `GSS_S_BAD_NAME`.  The principal string
is not in a form acceptable to `GSS_C_NT_HOSTBASED_SERVICE`
(`service@host`) or `GSS_C_NT_KRB5_PRINCIPAL_NAME`
(`service/host@REALM`).

##### gss_bad_mech

The GSS mechanism the caller asked for is not available.  Either
the krb5 GSS-API mech (gssapi-krb5) is not installed, or the
mech list ordering is wrong.

##### gss_no_cred

`gss_acquire_cred` or `gss_init_sec_context` returned
`GSS_S_NO_CRED`.  No usable initiator credential is available --
either there is no TGT in the user's ccache, or the machine
credential path can't see the keytab.

The reviewer flagged that this code is indistinguishable from "KCM
ccache daemon is down" at the GSS-API level, so this taxonomy
intentionally collapses both into one symbol.

##### gss_defective_token

Server returned a token that GSS-API could not parse.  Indicates a
server-side GSS bug or wire corruption.  Capture the exchange and
inspect the server logs.

##### gss_defective_cred

Local credential is malformed.  Re-run `kinit`; if persistent, file
a libkrb5 bug.

##### gss_cred_expired

The GSS credential expired between when the context was started and
when a call was made.  Long-lived NFS mounts need automatic
renewal (sssd, k5start) or a fresh `kinit` cycle.

##### gss_context_expired

The GSS security context itself expired mid-session.  The server
will return `RPCSEC_GSS_CTXPROBLEM` and the client should
re-establish the context.  If the client doesn't recover, check
the rpc.gssd / gssproxy logs.

##### gss_bad_mic

`gss_verify_mic` on a server reply failed.  Indicates wire
corruption, replay, or context-vs-key desync.  Capture and inspect
the GSS exchange.

For krb5i, this is the principal failure mode -- if the server's
MIC over the reply args doesn't verify, the client cannot trust
the response body.

##### gss_bad_sig

`gss_unwrap` reported a bad signature on a wrapped reply.  Same
root causes as `gss_bad_mic`; specific to krb5p.

##### gss_init_failed

Generic catch-all for `gss_init_sec_context` failures that the
classifier couldn't map to a more specific code.  Run with
`--krb5-trace` and look for the underlying minor-status reason.

#### RPCSEC_GSS wire (RFC 2203)

##### rpcsec_vers_mismatch

Client and server disagree on the RPCSEC_GSS protocol version
(should be 1 for both).  Check the server-side gssd or NFS daemon
version.

##### rpcsec_bad_cred

Server rejected the RPCSEC_GSS credential structure.  Wire-format
issue in the credential body or in the context handle.

##### rpcsec_gss_failed

Generic server-side rejection of an RPCSEC_GSS call after the
credential parsed.  Check server NFS / gssd logs.

##### rpcsec_ctxproblem

Server returned `RPCSEC_GSS_CTXPROBLEM`: the context the client
named is expired or unknown.  Most common cause under load is the
client's seq_num drifting outside the server's replay window.  The
client should re-establish the context.

If `--stress` mode surfaces this within the first few iterations,
the server's replay handling is broken.  If it surfaces only after
hours of activity, the client failed to renew the GSS context
when its underlying Kerberos credential expired.

##### rpcsec_credproblem

Server returned `RPCSEC_GSS_CREDPROBLEM`: the credentials
underlying the GSS context have expired (typically the user's TGT).
Refresh the Kerberos credentials and retry.

##### rpcsec_replay

Server's RPCSEC_GSS replay window detected a duplicate seq_num.
Default window size is 32; concurrent calls on a shared context
can interleave seq_nums in a way that overflows it.  Use a fresh
context per worker, or throttle concurrency.

##### replay_cache_perm

The server-side replay cache file (`/var/tmp/nfs_*` or the krb5
rcache directory) is owned by the wrong uid or is not writeable.
Symptom: every authenticated NFS call after the first one fails
with `GSS_S_DUPLICATE_TOKEN`.  Extremely common, frequently
misdiagnosed as a Kerberos problem.

```
ls -l /var/tmp/nfs_*    # check ownership
ls -lZ /var/tmp/nfs_*   # and SELinux label
```

Fix: remove the cache files and restart `rpc.gssd` / `gssproxy` so
they are recreated with correct ownership.

##### wrongsec

Server returned `NFS4ERR_WRONGSEC` for the requested operation.
The mount used the wrong `sec=` flavor for this export.  The client
should re-try via SECINFO negotiation, or mount with the flavor the
server advertises.

The reviewer flagged this as the single most common production
krb5+NFS failure.  The taxonomy entry exists; an automated probe
that deliberately exercises SECINFO negotiation is a follow-up
addition (current `nfs_krb5_test` does not yet trigger SECINFO
on its own).

##### secinfo_empty

`SECINFO` returned an empty acceptable-flavor list.  The server
has no acceptable security flavor for this export -- check
server-side `sec=` configuration and the client's offered flavors.

Like `wrongsec`, the taxonomy entry exists but is reserved for a
future automated probe.

##### null_rejected

Server rejected an authenticated NULL RPC over RPCSEC_GSS.  This
indicates the server accepted context establishment but rejected
the first DATA call.  Check `sec=` flavor agreement and server NFS
logs.

#### Identity mapping (post-auth)

##### idmap_domain_mismatch

Client and server NFSv4 idmap domains disagree.  Files appear to
exist (the krb5 context is fine) but every uid/gid maps to
`nobody:nobody`.

```
# /etc/idmapd.conf
[General]
Domain = example.com   # must match the server's domain
```

Or for the modern nfsidmap-based path:

```
# /etc/nfs.conf
[nfsd]
v4-id-mapping-domain = example.com
```

##### idmap_nobody

Files map to `nobody:nobody` despite a working krb5 context.
Symptom of `idmap_domain_mismatch` or a broken nfsidmap plugin.

```
nfsidmap -d              # show the configured domain
journalctl | grep nfsidmap
```

The reviewer was specific: `idmap_nobody` is a symptom bucket, not
a distinct cause.  It exists in the taxonomy as a diagnostic flag
that points the user at `idmap_domain_mismatch` and
`idmap_plugin_failed`.

##### idmap_plugin_failed

An nfsidmap plugin (sss / umich_ldap / static) failed to load or
returned an error.

```
# /etc/idmapd.conf (legacy)
[Translation]
Method = sss

# inspect the plugin chain
nfsidmap -d
```

Watch `journalctl` for nfsidmap errors after triggering the failure.

##### idmapd_not_running

`rpc.idmapd` is not running.  This applies only to legacy
NFSv4 client id mapping configurations; modern systems use the
`nfsidmap` plugin model where no daemon is required.

```
systemctl enable --now nfs-idmapd
```

#### Cross-domain aggregates

##### mixed (krb5)

More than one distinct krb5 failure class occurred in the same run.
Inspect the per-iteration `[ERROR ...]` blocks above the summary.

##### internal (krb5)

A tool internal error (out of memory, transport failure, bad
command-line argument).  Not a krb5 problem.  File a bug against
`nfs-test-tools`.

### A Kerberos debugging checklist

When everything is broken and you don't know where to start:

1. **Pre-flight:** `nfs_krb5_test --diagnose` checks the local
   environment (krb5.conf, keytab, FQDN, gssproxy, nfsidmap).
2. **Time:** `chronyc tracking` on both ends.  >5 min skew is an
   instant fail.
3. **Identity:** `kinit user@REALM`, `klist`, `kvno nfs/<host>` --
   verify the chain works independently of NFS.
4. **Keytab:** `klist -k /etc/krb5.keytab | grep nfs/` confirms
   the service principal is present and what kvno it carries.
5. **GSS provider:** `systemctl status gssproxy rpc-gssd` -- one
   should be active.
6. **Active probe:** `nfs_krb5_test --host server --tls-info` for
   the basic flavor, then `--sec krb5i` and `--sec krb5p` to verify
   integrity and privacy services.
7. **Trace:** `nfs_krb5_test --host server --krb5-trace
   /tmp/krb5.log --verbose` for in-process libkrb5 detail.  For
   kernel-side traces use `rpcdebug -m rpc -s auth` plus
   `journalctl -u rpc-gssd -f`.
8. **Stress:** `nfs_krb5_test --host server --iterations 1000
   --stress --sec krb5p` to surface intermittent server-side
   failures (replay cache, context handling under load).
9. **Idmap:** if files appear as `nobody:nobody` after a successful
   mount, the krb5 path is fine; debug the idmap layer instead.
10. **Wire capture:** `tshark -Y "rpcgss || krb"` to see the
    GSS-API exchange and the RPCSEC_GSS reject reasons on the wire.

If you get to step 10 and still don't know what's wrong, the
failure is probably in cross-realm trust, KDC database state, or
SELinux on the server.  Capture everything and file an upstream
bug.

## References

- **RFC 9289** -- Towards Remote Procedure Call Encryption By Default
- **RFC 5246 / 8446** -- TLS 1.2 / 1.3
- **RFC 2203** -- RPCSEC_GSS Protocol Specification
- **RFC 4120** -- The Kerberos Network Authentication Service (V5)
- **RFC 4121** -- The Kerberos Version 5 GSS-API Mechanism
- **RFC 2744** -- Generic Security Service API Version 2
- `tlshd(8)`, `tlshd.conf(5)` man pages
- `rpc.gssd(8)`, `gssproxy(8)`, `gssproxy.conf(5)` man pages
- `krb5.conf(5)`, `kadmin(1)`, `klist(1)`, `kinit(1)` man pages
- `nfsidmap(8)`, `idmapd.conf(5)` man pages
- Kernel docs: `Documentation/networking/tls.html` (kernel TLS)
- Kernel docs: `Documentation/filesystems/nfs/` (NFS internals)
- `ktls-utils` upstream: https://github.com/oracle/ktls-utils
- MIT Kerberos: https://web.mit.edu/kerberos/
- Wireshark TLS decryption guide: https://wiki.wireshark.org/TLS
