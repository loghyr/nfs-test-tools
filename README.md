<!-- SPDX-License-Identifier: Apache-2.0 -->

# nfs-test-tools — protocol-level NFS test utilities

A collection of tools for testing NFS server implementations at
the protocol level: TLS/STARTTLS stress, Kerberos authentication
verification, mount exerciser, and RPC diagnostics.

## Tools

| Tool | Purpose |
|------|---------|
| `nfs_tls_test` | TLS and STARTTLS (RFC 9289) stress testing |
| `nfs_krb5_test` | Kerberos/RPCSEC_GSS authentication verification |

## Quick Start

```bash
mkdir -p m4 && autoreconf -fi
mkdir build && cd build
../configure
make -j$(nproc)

# TLS stress test
./nfs_tls_test --host server --port 2049 --iterations 1000

# Kerberos auth test
./nfs_krb5_test --host server --principal nfs/server@REALM
```

## License

Apache-2.0. See [LICENSE](LICENSE) for the full text.
