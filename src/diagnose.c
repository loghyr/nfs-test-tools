/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * diagnose.c -- local pre-flight checks for NFS-over-TLS readiness.
 *
 * See diagnose.h for the contract.  Each check prints one line:
 *   DIAG: <name>: <PASS|FAIL|WARN>: <detail>
 * and contributes to the overall verdict (FAIL > WARN > PASS).
 */

#include "diagnose.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

enum verdict { V_PASS = 0, V_WARN = 2, V_FAIL = 1 };

static enum verdict combine(enum verdict a, enum verdict b)
{
    if (a == V_FAIL || b == V_FAIL) return V_FAIL;
    if (a == V_WARN || b == V_WARN) return V_WARN;
    return V_PASS;
}

static const char *verdict_str(enum verdict v)
{
    switch (v) {
    case V_PASS: return "PASS";
    case V_WARN: return "WARN";
    case V_FAIL: return "FAIL";
    }
    return "?";
}

static void emit(const char *check, enum verdict v, const char *detail)
{
    printf("DIAG: %s: %s: %s\n", check, verdict_str(v), detail);
}

/*
 * file_exists -- stat() and report whether a path exists and is a regular
 * file.  Returns true on success.
 */
static bool file_exists(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    return S_ISREG(st.st_mode);
}

/* --- individual checks --- */

/*
 * Linux kernel version.  Parse uname -r and require >= 6.5 (the floor
 * for any NFS-over-TLS support); recommend >= 6.12 (where major fixes
 * landed).  Non-Linux returns WARN.
 */
static enum verdict check_kernel_version(void)
{
    struct utsname un;
    if (uname(&un) != 0) {
        emit("kernel-version", V_WARN, "uname() failed");
        return V_WARN;
    }

    if (strcmp(un.sysname, "Linux") != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "non-Linux (%s); see FreeBSD docs",
                 un.sysname);
        emit("kernel-version", V_WARN, buf);
        return V_WARN;
    }

    int major = 0, minor = 0;
    if (sscanf(un.release, "%d.%d", &major, &minor) < 2) {
        char buf[128];
        snprintf(buf, sizeof(buf), "unparseable release string: %s",
                 un.release);
        emit("kernel-version", V_WARN, buf);
        return V_WARN;
    }

    char detail[128];
    snprintf(detail, sizeof(detail), "Linux %d.%d (%s)",
             major, minor, un.release);

    if (major < 6 || (major == 6 && minor < 5)) {
        emit("kernel-version", V_FAIL, detail);
        return V_FAIL;
    }
    if (major == 6 && minor < 12) {
        char warn[200];
        snprintf(warn, sizeof(warn),
                 "%s -- 6.12+ recommended for stable client behaviour",
                 detail);
        emit("kernel-version", V_WARN, warn);
        return V_WARN;
    }

    emit("kernel-version", V_PASS, detail);
    return V_PASS;
}

/*
 * Check that CONFIG_SUNRPC_TLS is enabled.  Look in /boot/config-$(uname -r)
 * if available; many distros don't ship the kernel config, in which case
 * we have to skip the check.
 */
static enum verdict check_sunrpc_tls(void)
{
    struct utsname un;
    if (uname(&un) != 0)
        return V_WARN;

    char path[256];
    snprintf(path, sizeof(path), "/boot/config-%s", un.release);

    FILE *fp = fopen(path, "re");
    if (!fp) {
        char buf[300];
        snprintf(buf, sizeof(buf), "no kernel config at %s (skipping)", path);
        emit("kernel-config", V_WARN, buf);
        return V_PASS;  /* don't penalise systems that don't ship the config */
    }

    enum verdict v = V_FAIL;
    const char *detail = "CONFIG_SUNRPC_TLS not found";
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "CONFIG_SUNRPC_TLS=", 18) == 0) {
            if (line[18] == 'y' || line[18] == 'Y') {
                v = V_PASS;
                detail = "CONFIG_SUNRPC_TLS=y";
            } else if (line[18] == 'm') {
                v = V_PASS;
                detail = "CONFIG_SUNRPC_TLS=m (module)";
            }
            break;
        }
    }
    fclose(fp);

    emit("kernel-config", v, detail);
    return v;
}

/*
 * tls module loaded.  Read /proc/modules; if absent, skip.
 */
static enum verdict check_tls_module(void)
{
    FILE *fp = fopen("/proc/modules", "re");
    if (!fp) {
        emit("tls-module", V_WARN, "/proc/modules unavailable");
        return V_PASS;
    }

    enum verdict v = V_WARN;
    const char *detail = "tls module not in /proc/modules (may be built in)";
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "tls ", 4) == 0) {
            v = V_PASS;
            detail = "tls module loaded";
            break;
        }
    }
    fclose(fp);

    emit("tls-module", v, detail);
    return v == V_WARN ? V_PASS : v;  /* WARN here is acceptable */
}

/*
 * tlshd presence and runtime state.
 *   Step 1: is the binary in PATH?
 *   Step 2: is the systemd unit active?  We can't talk to systemd from a
 *           portable C program, but we can spot the typical install paths
 *           and check whether the daemon is alive via /proc.
 */
static enum verdict check_tlshd(void)
{
    /* Common install locations */
    static const char *paths[] = {
        "/usr/sbin/tlshd",
        "/usr/local/sbin/tlshd",
        "/sbin/tlshd",
        NULL,
    };

    bool found = false;
    char found_path[128] = {0};
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0) {
            found = true;
            snprintf(found_path, sizeof(found_path), "%s", paths[i]);
            break;
        }
    }

    if (!found) {
        emit("tlshd-installed", V_FAIL,
             "tlshd not found (install ktls-utils)");
        return V_FAIL;
    }
    emit("tlshd-installed", V_PASS, found_path);

    /* Check whether tlshd is running.  We shell out to pgrep rather
     * than scanning /proc ourselves to keep this file header-light. */
    int rc = system("pgrep -x tlshd >/dev/null 2>&1");
    if (rc == 0) {
        emit("tlshd-running", V_PASS, "tlshd process found");
        return V_PASS;
    }
    emit("tlshd-running", V_WARN,
         "tlshd not running (systemctl start tlshd)");
    return V_WARN;
}

/*
 * OpenSSL TLS 1.3 support and ALPN support.  Both have been in OpenSSL
 * since 1.1.1, so this is mostly a sanity check that we linked against
 * a real OpenSSL.
 */
static enum verdict check_openssl(void)
{
    long ver = OPENSSL_VERSION_NUMBER;
    char buf[128];
    snprintf(buf, sizeof(buf), "%s (0x%08lx)",
             OpenSSL_version(OPENSSL_VERSION), ver);

    if (ver < 0x10101000L) {
        emit("openssl-version", V_FAIL, buf);
        return V_FAIL;
    }
    emit("openssl-version", V_PASS, buf);
    return V_PASS;
}

/* --- public API --- */

int diagnose_run(void)
{
    enum verdict total = V_PASS;

    printf("nfs-test-tools diagnose: pre-flight checks for NFS-over-TLS\n");
    printf("------------------------------------------------------------\n");

    total = combine(total, check_kernel_version());
    total = combine(total, check_sunrpc_tls());
    total = combine(total, check_tls_module());
    total = combine(total, check_tlshd());
    total = combine(total, check_openssl());

    printf("------------------------------------------------------------\n");
    printf("Overall: %s\n", verdict_str(total));

    return (int)total;
}

/* --- cert-info mode --- */

/*
 * load_x509 -- load a PEM cert from path.  Returns NULL on error
 * and prints the OpenSSL error reason via emit().
 */
static X509 *load_x509(const char *path)
{
    FILE *fp = fopen(path, "re");
    if (!fp) {
        char buf[300];
        snprintf(buf, sizeof(buf), "%s: %s", path, strerror(errno));
        emit("cert-load", V_FAIL, buf);
        return NULL;
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) {
        char buf[300];
        snprintf(buf, sizeof(buf), "%s: PEM parse failed", path);
        emit("cert-load", V_FAIL, buf);
        return NULL;
    }
    return cert;
}

static EVP_PKEY *load_pkey(const char *path)
{
    FILE *fp = fopen(path, "re");
    if (!fp) {
        char buf[300];
        snprintf(buf, sizeof(buf), "%s: %s", path, strerror(errno));
        emit("key-load", V_FAIL, buf);
        return NULL;
    }
    EVP_PKEY *pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pk) {
        char buf[300];
        snprintf(buf, sizeof(buf), "%s: PEM parse failed", path);
        emit("key-load", V_FAIL, buf);
        return NULL;
    }
    return pk;
}

/*
 * Print the cert subject, issuer, validity period, and SAN.
 * Returns the verdict for the validity period (cert expired -> FAIL).
 */
static enum verdict report_cert_basics(X509 *cert)
{
    enum verdict v = V_PASS;

    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *iss  = X509_NAME_oneline(X509_get_issuer_name(cert),  NULL, 0);
    if (subj) {
        emit("cert-subject", V_PASS, subj);
        OPENSSL_free(subj);
    }
    if (iss) {
        emit("cert-issuer", V_PASS, iss);
        OPENSSL_free(iss);
    }

    /* Validity */
    const ASN1_TIME *nb = X509_get0_notBefore(cert);
    const ASN1_TIME *na = X509_get0_notAfter(cert);

    int day = 0, sec = 0;
    if (ASN1_TIME_diff(&day, &sec, NULL, nb) && (day > 0 || sec > 0)) {
        emit("cert-validity", V_FAIL, "not yet valid (notBefore in future)");
        v = V_FAIL;
    } else if (ASN1_TIME_diff(&day, &sec, NULL, na) && day < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expired %d day(s) ago", -day);
        emit("cert-validity", V_FAIL, buf);
        v = V_FAIL;
    } else if (day < 30) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expires in %d day(s)", day);
        emit("cert-validity", V_WARN, buf);
        v = combine(v, V_WARN);
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "valid for %d more day(s)", day);
        emit("cert-validity", V_PASS, buf);
    }

    /* SAN */
    STACK_OF(GENERAL_NAME) *sans = X509_get_ext_d2i(cert,
        NID_subject_alt_name, NULL, NULL);
    if (!sans) {
        emit("cert-san", V_WARN, "no subjectAltName extension");
        v = combine(v, V_WARN);
    } else {
        char buf[1024];
        size_t pos = 0;
        int n = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < n && pos < sizeof(buf) - 32; i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (!gn) continue;
            if (gn->type == GEN_DNS) {
                pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos,
                    "%sDNS:%.*s",
                    pos ? ", " : "",
                    ASN1_STRING_length(gn->d.dNSName),
                    (const char *)ASN1_STRING_get0_data(gn->d.dNSName));
            } else if (gn->type == GEN_IPADD) {
                const unsigned char *ip = ASN1_STRING_get0_data(gn->d.iPAddress);
                int iplen = ASN1_STRING_length(gn->d.iPAddress);
                if (iplen == 4) {
                    pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos,
                        "%sIP:%u.%u.%u.%u",
                        pos ? ", " : "",
                        ip[0], ip[1], ip[2], ip[3]);
                } else if (iplen == 16) {
                    pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos,
                        "%sIP:(IPv6)", pos ? ", " : "");
                }
            }
        }
        emit("cert-san", V_PASS, buf);
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    return v;
}

/*
 * Verify cert/key modulus match.
 */
static enum verdict report_cert_key_match(X509 *cert, EVP_PKEY *key)
{
    if (X509_check_private_key(cert, key) == 1) {
        emit("cert-key-match", V_PASS, "certificate and key match");
        return V_PASS;
    }
    char buf[256];
    unsigned long e = ERR_peek_last_error();
    if (e)
        ERR_error_string_n(e, buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "modulus mismatch");
    emit("cert-key-match", V_FAIL, buf);
    return V_FAIL;
}

/*
 * Verify the cert against a CA bundle using openssl's chain validation.
 */
static enum verdict report_chain(X509 *cert, const char *ca_path)
{
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        emit("cert-chain", V_FAIL, "X509_STORE_new failed");
        return V_FAIL;
    }

    if (X509_STORE_load_locations(store, ca_path, NULL) != 1) {
        char buf[300];
        snprintf(buf, sizeof(buf), "load CA from %s failed", ca_path);
        emit("cert-chain", V_FAIL, buf);
        X509_STORE_free(store);
        return V_FAIL;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        emit("cert-chain", V_FAIL, "X509_STORE_CTX_new failed");
        X509_STORE_free(store);
        return V_FAIL;
    }

    X509_STORE_CTX_init(ctx, store, cert, NULL);
    int ok = X509_verify_cert(ctx);
    enum verdict v;
    if (ok == 1) {
        emit("cert-chain", V_PASS, "verified against CA");
        v = V_PASS;
    } else {
        int err = X509_STORE_CTX_get_error(ctx);
        const char *reason = X509_verify_cert_error_string(err);
        char buf[300];
        snprintf(buf, sizeof(buf), "verify failed: %s", reason);
        emit("cert-chain", V_FAIL, buf);
        v = V_FAIL;
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return v;
}

/*
 * Check that all required SAN entries are present.
 * required is comma-separated "IP:..."/"DNS:..."/bare values.
 */
static enum verdict report_required_san(X509 *cert, const char *required)
{
    STACK_OF(GENERAL_NAME) *sans = X509_get_ext_d2i(cert,
        NID_subject_alt_name, NULL, NULL);
    if (!sans) {
        emit("cert-required-san", V_FAIL, "cert has no SAN extension");
        return V_FAIL;
    }

    char *copy = strdup(required);
    if (!copy) {
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
        return V_FAIL;
    }

    enum verdict v = V_PASS;
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;

        int type_hint = 0;
        const char *value = tok;
        if (strncasecmp(tok, "IP:", 3) == 0) {
            type_hint = GEN_IPADD;
            value = tok + 3;
        } else if (strncasecmp(tok, "DNS:", 4) == 0) {
            type_hint = GEN_DNS;
            value = tok + 4;
        }

        bool found = false;
        int n = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < n && !found; i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (!gn) continue;
            if ((type_hint == 0 || type_hint == GEN_DNS) &&
                gn->type == GEN_DNS) {
                int dl = ASN1_STRING_length(gn->d.dNSName);
                const char *d = (const char *)
                    ASN1_STRING_get0_data(gn->d.dNSName);
                if (dl > 0 && (size_t)dl == strlen(value) &&
                    strncasecmp(d, value, (size_t)dl) == 0)
                    found = true;
            }
            if (!found && (type_hint == 0 || type_hint == GEN_IPADD) &&
                gn->type == GEN_IPADD) {
                const unsigned char *ip =
                    ASN1_STRING_get0_data(gn->d.iPAddress);
                int iplen = ASN1_STRING_length(gn->d.iPAddress);
                char ipstr[64];
                if (iplen == 4) {
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                             ip[0], ip[1], ip[2], ip[3]);
                    if (strcmp(ipstr, value) == 0)
                        found = true;
                }
                /* IPv6 string compare omitted for brevity; could use inet_ntop */
            }
        }

        if (!found) {
            char buf[200];
            snprintf(buf, sizeof(buf), "missing: %s", tok);
            emit("cert-required-san", V_FAIL, buf);
            v = V_FAIL;
            break;
        }
    }

    if (v == V_PASS)
        emit("cert-required-san", V_PASS, "all required entries present");

    free(copy);
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    return v;
}

int cert_info_run(const char *cert_path, const char *key_path,
                  const char *ca_path, const char *required_san)
{
    enum verdict total = V_PASS;

    printf("nfs-test-tools cert-info: certificate diagnostics\n");
    printf("------------------------------------------------------------\n");

    if (!cert_path) {
        emit("cert-load", V_FAIL, "no --cert specified");
        return 1;
    }

    if (!file_exists(cert_path)) {
        char buf[300];
        snprintf(buf, sizeof(buf), "%s: not a regular file", cert_path);
        emit("cert-load", V_FAIL, buf);
        return 1;
    }

    X509 *cert = load_x509(cert_path);
    if (!cert)
        return 1;

    total = combine(total, report_cert_basics(cert));

    if (key_path) {
        if (!file_exists(key_path)) {
            char buf[300];
            snprintf(buf, sizeof(buf), "%s: not a regular file", key_path);
            emit("key-load", V_FAIL, buf);
            total = V_FAIL;
        } else {
            EVP_PKEY *key = load_pkey(key_path);
            if (!key) {
                total = V_FAIL;
            } else {
                total = combine(total, report_cert_key_match(cert, key));
                EVP_PKEY_free(key);
            }
        }
    }

    if (ca_path) {
        if (!file_exists(ca_path)) {
            char buf[300];
            snprintf(buf, sizeof(buf), "%s: not a regular file", ca_path);
            emit("ca-load", V_FAIL, buf);
            total = V_FAIL;
        } else {
            total = combine(total, report_chain(cert, ca_path));
        }
    }

    if (required_san) {
        total = combine(total, report_required_san(cert, required_san));
    }

    X509_free(cert);

    printf("------------------------------------------------------------\n");
    printf("Overall: %s\n", verdict_str(total));
    return (int)total;
}
