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

## References

- **RFC 9289** -- Towards Remote Procedure Call Encryption By Default
- **RFC 5246 / 8446** -- TLS 1.2 / 1.3
- `tlshd(8)`, `tlshd.conf(5)` man pages
- Kernel docs: `Documentation/networking/tls.html` (kernel TLS)
- Kernel docs: `Documentation/filesystems/nfs/` (NFS internals)
- `ktls-utils` upstream: https://github.com/oracle/ktls-utils
- Wireshark TLS decryption guide: https://wiki.wireshark.org/TLS
