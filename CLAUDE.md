<!-- SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only -->

# nfs-test-tools — Claude Code Project Instructions

## Architecture

- `src/nfs_tls_test.c` — TLS/STARTTLS stress tool (RFC 9289)
- `src/nfs_krb5_test.c` — Kerberos/RPCSEC_GSS auth test
- `src/tls_client.c` — shared TLS client library

## License

- All code: dual `BSD-2-Clause OR GPL-2.0-only` (recipient's choice)
- SPDX headers required on all files: `SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only`
- Co-Authored-By lines are permitted in this repo

## Git conventions

- Always sign off: `git commit -s`
- One concern per commit
