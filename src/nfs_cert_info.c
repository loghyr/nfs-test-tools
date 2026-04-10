/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfs_cert_info.c -- standalone certificate validation tool.
 *
 * Validates a TLS certificate (and optionally a private key, CA bundle,
 * and required SAN entries) without performing any network IO.  This
 * is the openssl-equivalent of the cert-troubleshooting commands in
 * TROUBLESHOOTING.md, packaged as one tool invocation.
 *
 * Usage:
 *   nfs_cert_info --cert FILE [options]
 *
 * Options:
 *   --cert FILE         PEM certificate to inspect (required)
 *   --key  FILE         PEM private key; verified to match the cert
 *   --ca   FILE         PEM CA bundle; cert is verified against it
 *   --require-san LIST  Comma-separated 'IP:..,DNS:..' entries; all
 *                       must be present in the cert SAN
 *
 * Exit status:
 *   0 = all checks pass
 *   1 = at least one check failed
 *   2 = at least one check warned
 */

#include "diagnose.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --cert FILE [options]\n"
        "\n"
        "Options:\n"
        "  --cert FILE         PEM certificate to inspect (required)\n"
        "  --key FILE          PEM private key (verified against cert)\n"
        "  --ca FILE           PEM CA bundle (cert is verified against it)\n"
        "  --require-san LIST  Required SAN entries (e.g. 'IP:10.0.0.1,DNS:host')\n"
        "\n"
        "Exit: 0=PASS, 1=FAIL, 2=WARN\n",
        prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "cert",        required_argument, NULL, 'c' },
        { "key",         required_argument, NULL, 'k' },
        { "ca",          required_argument, NULL, 'C' },
        { "require-san", required_argument, NULL, 'S' },
        { NULL, 0, NULL, 0 }
    };

    const char *cert = NULL, *key = NULL, *ca = NULL, *required_san = NULL;
    int ch;
    while ((ch = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'c': cert         = optarg; break;
        case 'k': key          = optarg; break;
        case 'C': ca           = optarg; break;
        case 'S': required_san = optarg; break;
        default:  usage(argv[0]);
        }
    }

    if (!cert)
        usage(argv[0]);

    return cert_info_run(cert, key, ca, required_san);
}
