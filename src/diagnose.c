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
#include <sys/wait.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/*
 * Local convenience aliases so the existing check function bodies
 * (and report_* helpers below) keep their old, terse spelling.
 * The public diag_emit / diag_combine / diag_verdict_str symbols
 * live in the registry section below.
 */
#define emit diag_emit
#define combine diag_combine
#define verdict_str diag_verdict_str

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
static enum diag_verdict check_kernel_version(void)
{
	struct utsname un;
	if (uname(&un) != 0) {
		emit("kernel-version", DIAG_WARN, "uname() failed");
		return DIAG_WARN;
	}

	if (strcmp(un.sysname, "Linux") != 0) {
		char buf[128];
		snprintf(buf, sizeof(buf), "non-Linux (%s); see FreeBSD docs",
			 un.sysname);
		emit("kernel-version", DIAG_WARN, buf);
		return DIAG_WARN;
	}

	int major = 0, minor = 0;
	if (sscanf(un.release, "%d.%d", &major, &minor) < 2) {
		char buf[128];
		snprintf(buf, sizeof(buf), "unparseable release string: %s",
			 un.release);
		emit("kernel-version", DIAG_WARN, buf);
		return DIAG_WARN;
	}

	char detail[128];
	snprintf(detail, sizeof(detail), "Linux %d.%d (%s)", major, minor,
		 un.release);

	if (major < 6 || (major == 6 && minor < 5)) {
		emit("kernel-version", DIAG_FAIL, detail);
		return DIAG_FAIL;
	}
	if (major == 6 && minor < 12) {
		char warn[200];
		snprintf(warn, sizeof(warn),
			 "%s -- 6.12+ recommended for stable client behaviour",
			 detail);
		emit("kernel-version", DIAG_WARN, warn);
		return DIAG_WARN;
	}

	emit("kernel-version", DIAG_PASS, detail);
	return DIAG_PASS;
}

/*
 * Check that CONFIG_SUNRPC_TLS is enabled.  Look in /boot/config-$(uname -r)
 * if available; many distros don't ship the kernel config, in which case
 * we have to skip the check.
 */
static enum diag_verdict check_sunrpc_tls(void)
{
	struct utsname un;
	if (uname(&un) != 0)
		return DIAG_WARN;

	char path[256];
	snprintf(path, sizeof(path), "/boot/config-%s", un.release);

	FILE *fp = fopen(path, "re");
	if (!fp) {
		char buf[300];
		snprintf(buf, sizeof(buf), "no kernel config at %s (skipping)",
			 path);
		emit("kernel-config", DIAG_WARN, buf);
		return DIAG_PASS; /* don't penalise systems that don't ship the config */
	}

	enum diag_verdict v = DIAG_FAIL;
	const char *detail = "CONFIG_SUNRPC_TLS not found";
	char line[512];
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "CONFIG_SUNRPC_TLS=", 18) == 0) {
			if (line[18] == 'y' || line[18] == 'Y') {
				v = DIAG_PASS;
				detail = "CONFIG_SUNRPC_TLS=y";
			} else if (line[18] == 'm') {
				v = DIAG_PASS;
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
static enum diag_verdict check_tls_module(void)
{
	FILE *fp = fopen("/proc/modules", "re");
	if (!fp) {
		emit("tls-module", DIAG_WARN, "/proc/modules unavailable");
		return DIAG_PASS;
	}

	enum diag_verdict v = DIAG_WARN;
	const char *detail =
		"tls module not in /proc/modules (may be built in)";
	char line[256];
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "tls ", 4) == 0) {
			v = DIAG_PASS;
			detail = "tls module loaded";
			break;
		}
	}
	fclose(fp);

	emit("tls-module", v, detail);
	return v == DIAG_WARN ? DIAG_PASS : v; /* WARN here is acceptable */
}

/*
 * tlshd presence and runtime state.
 *   Step 1: is the binary in PATH?
 *   Step 2: is the systemd unit active?  We can't talk to systemd from a
 *           portable C program, but we can spot the typical install paths
 *           and check whether the daemon is alive via /proc.
 */
static enum diag_verdict check_tlshd(void)
{
	/* Common install locations */
	static const char *paths[] = {
		"/usr/sbin/tlshd",
		"/usr/local/sbin/tlshd",
		"/sbin/tlshd",
		NULL,
	};

	bool found = false;
	char found_path[128] = { 0 };
	for (int i = 0; paths[i]; i++) {
		if (access(paths[i], X_OK) == 0) {
			found = true;
			snprintf(found_path, sizeof(found_path), "%s",
				 paths[i]);
			break;
		}
	}

	if (!found) {
		emit("tlshd-installed", DIAG_FAIL,
		     "tlshd not found (install ktls-utils)");
		return DIAG_FAIL;
	}
	emit("tlshd-installed", DIAG_PASS, found_path);

	/*
     * Check whether tlshd is running.  We shell out to pgrep rather
     * than scanning /proc ourselves to keep this file header-light.
     *
     * Distinguish three cases:
     *   - exit 0      : tlshd is running
     *   - exit 1      : tlshd is not running
     *   - exit 127    : pgrep is not installed (cannot check)
     *   - rc == -1    : system() itself failed
     *
     * Without this distinction, a missing pgrep would be silently
     * misreported as "tlshd not running".
     */
	int rc = system("pgrep -x tlshd >/dev/null 2>&1");
	if (rc == -1) {
		emit("tlshd-running", DIAG_WARN, "system() failed");
		return DIAG_WARN;
	}
	if (WIFEXITED(rc)) {
		int code = WEXITSTATUS(rc);
		if (code == 0) {
			emit("tlshd-running", DIAG_PASS, "tlshd process found");
			return DIAG_PASS;
		}
		if (code == 127) {
			emit("tlshd-running", DIAG_WARN,
			     "cannot check (pgrep not installed)");
			return DIAG_WARN;
		}
	}
	emit("tlshd-running", DIAG_WARN,
	     "tlshd not running (systemctl start tlshd)");
	return DIAG_WARN;
}

/*
 * OpenSSL TLS 1.3 support and ALPN support.  Both have been in OpenSSL
 * since 1.1.1, so this is mostly a sanity check that we linked against
 * a real OpenSSL.
 */
static enum diag_verdict check_openssl(void)
{
	long ver = OPENSSL_VERSION_NUMBER;
	char buf[128];
	snprintf(buf, sizeof(buf), "%s (0x%08lx)",
		 OpenSSL_version(OPENSSL_VERSION), ver);

	if (ver < 0x10101000L) {
		emit("openssl-version", DIAG_FAIL, buf);
		return DIAG_FAIL;
	}
	emit("openssl-version", DIAG_PASS, buf);
	return DIAG_PASS;
}

/* --- TLS check registration -------------------------------------
 *
 * The shared verdict primitives (diag_emit / diag_combine /
 * diag_verdict_str) and the registry walker (diag_register /
 * diag_run) live in diag.c so that nfs_krb5_test can link them
 * without dragging OpenSSL into its build.  The TLS check function
 * bodies above use the historical short spellings (emit, combine,
 * verdict_str) via the macro shorthand at the top of this file.
 */

/*
 * One static const struct diag_check per existing check function.
 * The function names and check identifiers are unchanged from the
 * pre-registry implementation, so the per-line "DIAG: <name>:" output
 * is bit-for-bit identical when --diagnose runs against the TLS
 * domain.
 */
static const struct diag_check s_check_kernel_version = {
	.name = "kernel-version",
	.domains = DIAG_DOMAIN_TLS | DIAG_DOMAIN_KRB5,
	.run = check_kernel_version,
};
static const struct diag_check s_check_sunrpc_tls = {
	.name = "kernel-config",
	.domains = DIAG_DOMAIN_TLS,
	.run = check_sunrpc_tls,
};
static const struct diag_check s_check_tls_module = {
	.name = "tls-module",
	.domains = DIAG_DOMAIN_TLS,
	.run = check_tls_module,
};
static const struct diag_check s_check_tlshd = {
	.name = "tlshd",
	.domains = DIAG_DOMAIN_TLS,
	.run = check_tlshd,
};
static const struct diag_check s_check_openssl = {
	.name = "openssl-version",
	.domains = DIAG_DOMAIN_TLS,
	.run = check_openssl,
};

void diag_init_tls(void)
{
	diag_register(&s_check_kernel_version);
	diag_register(&s_check_sunrpc_tls);
	diag_register(&s_check_tls_module);
	diag_register(&s_check_tlshd);
	diag_register(&s_check_openssl);
}

/* --- backward-compatible diagnose_run --------------------------- */

int diagnose_run(void)
{
	diag_init_tls();
	return diag_run(DIAG_DOMAIN_TLS);
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
		emit("cert-load", DIAG_FAIL, buf);
		return NULL;
	}
	X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!cert) {
		char buf[300];
		snprintf(buf, sizeof(buf), "%s: PEM parse failed", path);
		emit("cert-load", DIAG_FAIL, buf);
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
		emit("key-load", DIAG_FAIL, buf);
		return NULL;
	}
	EVP_PKEY *pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!pk) {
		char buf[300];
		snprintf(buf, sizeof(buf), "%s: PEM parse failed", path);
		emit("key-load", DIAG_FAIL, buf);
		return NULL;
	}
	return pk;
}

/*
 * Print the cert subject, issuer, validity period, and SAN.
 * Returns the verdict for the validity period (cert expired -> FAIL).
 */
static enum diag_verdict report_cert_basics(X509 *cert)
{
	enum diag_verdict v = DIAG_PASS;

	char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	char *iss = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	if (subj) {
		emit("cert-subject", DIAG_PASS, subj);
		OPENSSL_free(subj);
	}
	if (iss) {
		emit("cert-issuer", DIAG_PASS, iss);
		OPENSSL_free(iss);
	}

	/* Validity */
	const ASN1_TIME *nb = X509_get0_notBefore(cert);
	const ASN1_TIME *na = X509_get0_notAfter(cert);

	int day = 0, sec = 0;
	if (ASN1_TIME_diff(&day, &sec, NULL, nb) && (day > 0 || sec > 0)) {
		emit("cert-validity", DIAG_FAIL,
		     "not yet valid (notBefore in future)");
		v = DIAG_FAIL;
	} else if (ASN1_TIME_diff(&day, &sec, NULL, na) && day < 0) {
		char buf[128];
		snprintf(buf, sizeof(buf), "expired %d day(s) ago", -day);
		emit("cert-validity", DIAG_FAIL, buf);
		v = DIAG_FAIL;
	} else if (day < 30) {
		char buf[128];
		snprintf(buf, sizeof(buf), "expires in %d day(s)", day);
		emit("cert-validity", DIAG_WARN, buf);
		v = combine(v, DIAG_WARN);
	} else {
		char buf[128];
		snprintf(buf, sizeof(buf), "valid for %d more day(s)", day);
		emit("cert-validity", DIAG_PASS, buf);
	}

	/* SAN */
	STACK_OF(GENERAL_NAME) *sans =
		X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (!sans) {
		emit("cert-san", DIAG_WARN, "no subjectAltName extension");
		v = combine(v, DIAG_WARN);
	} else {
		/*
         * Build a comma-separated SAN summary into buf.  Each snprintf
         * call must check both error (n < 0) and truncation (n >= avail)
         * before advancing pos -- otherwise pos can overshoot sizeof(buf)
         * and the next iteration writes past the end.
         */
		char buf[1024];
		size_t pos = 0;
		bool truncated = false;
		int n = sk_GENERAL_NAME_num(sans);
		for (int i = 0; i < n && !truncated; i++) {
			GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
			if (!gn)
				continue;

			size_t avail = sizeof(buf) - pos;
			int written = -1;
			if (gn->type == GEN_DNS) {
				const char *d =
					(const char *)ASN1_STRING_get0_data(
						gn->d.dNSName);
				int dl = ASN1_STRING_length(gn->d.dNSName);
				if (d && dl >= 0)
					written = snprintf(buf + pos, avail,
							   "%sDNS:%.*s",
							   pos ? ", " : "", dl,
							   d);
			} else if (gn->type == GEN_IPADD) {
				const unsigned char *ip =
					ASN1_STRING_get0_data(gn->d.iPAddress);
				int iplen = ASN1_STRING_length(gn->d.iPAddress);
				if (ip && iplen == 4) {
					written = snprintf(buf + pos, avail,
							   "%sIP:%u.%u.%u.%u",
							   pos ? ", " : "",
							   ip[0], ip[1], ip[2],
							   ip[3]);
				} else if (ip && iplen == 16) {
					char ip6[INET6_ADDRSTRLEN];
					if (inet_ntop(AF_INET6, ip, ip6,
						      sizeof(ip6)))
						written = snprintf(
							buf + pos, avail,
							"%sIP:%s",
							pos ? ", " : "", ip6);
				}
			}

			if (written < 0)
				continue;
			if ((size_t)written >= avail) {
				/* Truncated -- mark it and stop */
				if (avail > 0)
					buf[sizeof(buf) - 1] = '\0';
				/* Best-effort marker if there is room */
				if (pos + 5 < sizeof(buf))
					memcpy(buf + sizeof(buf) - 5, "...", 4);
				truncated = true;
				break;
			}
			pos += (size_t)written;
		}
		emit("cert-san", DIAG_PASS, buf);
		sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
	}

	return v;
}

/*
 * Verify cert/key modulus match.
 */
static enum diag_verdict report_cert_key_match(X509 *cert, EVP_PKEY *key)
{
	if (X509_check_private_key(cert, key) == 1) {
		emit("cert-key-match", DIAG_PASS, "certificate and key match");
		return DIAG_PASS;
	}
	char buf[256];
	unsigned long e = ERR_peek_last_error();
	if (e)
		ERR_error_string_n(e, buf, sizeof(buf));
	else
		snprintf(buf, sizeof(buf), "modulus mismatch");
	emit("cert-key-match", DIAG_FAIL, buf);
	return DIAG_FAIL;
}

/*
 * Verify the cert against a CA bundle using openssl's chain validation.
 */
static enum diag_verdict report_chain(X509 *cert, const char *ca_path)
{
	X509_STORE *store = X509_STORE_new();
	if (!store) {
		emit("cert-chain", DIAG_FAIL, "X509_STORE_new failed");
		return DIAG_FAIL;
	}

	if (X509_STORE_load_locations(store, ca_path, NULL) != 1) {
		char buf[300];
		snprintf(buf, sizeof(buf), "load CA from %s failed", ca_path);
		emit("cert-chain", DIAG_FAIL, buf);
		X509_STORE_free(store);
		return DIAG_FAIL;
	}

	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	if (!ctx) {
		emit("cert-chain", DIAG_FAIL, "X509_STORE_CTX_new failed");
		X509_STORE_free(store);
		return DIAG_FAIL;
	}

	X509_STORE_CTX_init(ctx, store, cert, NULL);
	int ok = X509_verify_cert(ctx);
	enum diag_verdict v;
	if (ok == 1) {
		emit("cert-chain", DIAG_PASS, "verified against CA");
		v = DIAG_PASS;
	} else {
		int err = X509_STORE_CTX_get_error(ctx);
		const char *reason = X509_verify_cert_error_string(err);
		char buf[300];
		snprintf(buf, sizeof(buf), "verify failed: %s", reason);
		emit("cert-chain", DIAG_FAIL, buf);
		v = DIAG_FAIL;
	}
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return v;
}

/*
 * Check that all required SAN entries are present.
 * required is comma-separated "IP:..."/"DNS:..."/bare values.
 */
static enum diag_verdict report_required_san(X509 *cert, const char *required)
{
	STACK_OF(GENERAL_NAME) *sans =
		X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (!sans) {
		emit("cert-required-san", DIAG_FAIL,
		     "cert has no SAN extension");
		return DIAG_FAIL;
	}

	char *copy = strdup(required);
	if (!copy) {
		sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
		return DIAG_FAIL;
	}

	enum diag_verdict v = DIAG_PASS;
	char *save = NULL;
	for (char *tok = strtok_r(copy, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ')
			tok++;

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
			if (!gn)
				continue;
			if ((type_hint == 0 || type_hint == GEN_DNS) &&
			    gn->type == GEN_DNS) {
				int dl = ASN1_STRING_length(gn->d.dNSName);
				const char *d =
					(const char *)ASN1_STRING_get0_data(
						gn->d.dNSName);
				if (dl > 0 && (size_t)dl == strlen(value) &&
				    strncasecmp(d, value, (size_t)dl) == 0)
					found = true;
			}
			if (!found &&
			    (type_hint == 0 || type_hint == GEN_IPADD) &&
			    gn->type == GEN_IPADD) {
				const unsigned char *ip =
					ASN1_STRING_get0_data(gn->d.iPAddress);
				int iplen = ASN1_STRING_length(gn->d.iPAddress);
				char ipstr[64];
				if (iplen == 4) {
					snprintf(ipstr, sizeof(ipstr),
						 "%u.%u.%u.%u", ip[0], ip[1],
						 ip[2], ip[3]);
					if (strcmp(ipstr, value) == 0)
						found = true;
				}
				/* IPv6 string compare omitted for brevity; could use inet_ntop */
			}
		}

		if (!found) {
			char buf[200];
			snprintf(buf, sizeof(buf), "missing: %s", tok);
			emit("cert-required-san", DIAG_FAIL, buf);
			v = DIAG_FAIL;
			break;
		}
	}

	if (v == DIAG_PASS)
		emit("cert-required-san", DIAG_PASS,
		     "all required entries present");

	free(copy);
	sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
	return v;
}

int cert_info_run(const char *cert_path, const char *key_path,
		  const char *ca_path, const char *required_san)
{
	enum diag_verdict total = DIAG_PASS;

	printf("nfs-test-tools cert-info: certificate diagnostics\n");
	printf("------------------------------------------------------------\n");

	if (!cert_path) {
		emit("cert-load", DIAG_FAIL, "no --cert specified");
		return 1;
	}

	if (!file_exists(cert_path)) {
		char buf[300];
		snprintf(buf, sizeof(buf), "%s: not a regular file", cert_path);
		emit("cert-load", DIAG_FAIL, buf);
		return 1;
	}

	X509 *cert = load_x509(cert_path);
	if (!cert)
		return 1;

	total = combine(total, report_cert_basics(cert));

	if (key_path) {
		if (!file_exists(key_path)) {
			char buf[300];
			snprintf(buf, sizeof(buf), "%s: not a regular file",
				 key_path);
			emit("key-load", DIAG_FAIL, buf);
			total = combine(total, DIAG_FAIL);
		} else {
			EVP_PKEY *key = load_pkey(key_path);
			if (!key) {
				total = combine(total, DIAG_FAIL);
			} else {
				total = combine(total, report_cert_key_match(
							       cert, key));
				EVP_PKEY_free(key);
			}
		}
	}

	if (ca_path) {
		if (!file_exists(ca_path)) {
			char buf[300];
			snprintf(buf, sizeof(buf), "%s: not a regular file",
				 ca_path);
			emit("ca-load", DIAG_FAIL, buf);
			total = combine(total, DIAG_FAIL);
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
