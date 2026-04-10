/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * diagnose_krb5.c -- Kerberos / RPCSEC_GSS pre-flight checks.
 *
 * Mirror of diagnose.c's TLS check set, registered into the same
 * diag_check registry under DIAG_DOMAIN_KRB5.  Built only when
 * HAVE_GSSAPI is defined (configure detects libgssapi-krb5).
 *
 * Implementation strategy: shell-out plus stat() / getent / pgrep
 * for the things that are easier to query that way.  No libkrb5
 * linkage is required for these checks -- the deeper integrations
 * (programmatically parsing krb5.conf, querying KDC reachability,
 * enctype intersection) live in nfs_krb5_test runtime classification,
 * not in the pre-flight pass.
 */

#include "diagnose.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>

/*
 * file_readable -- stat() and access() to confirm a path exists,
 * is a regular file, and is readable by the current uid.
 */
static int file_readable(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return 0;
	if (!S_ISREG(st.st_mode))
		return 0;
	return access(path, R_OK) == 0;
}

/*
 * run_silent -- shell out to a command, return WEXITSTATUS or -1.
 *
 * Distinguishes:
 *   -1            : system() itself failed
 *   127           : shell could not find the program
 *   anything else : the command's exit status
 *
 * Used to probe for binaries (`klist`, `pgrep`, `getent`, ...) without
 * pulling in their object files.
 */
static int run_silent(const char *cmd)
{
	int rc = system(cmd);
	if (rc == -1)
		return -1;
	if (!WIFEXITED(rc))
		return -1;
	return WEXITSTATUS(rc);
}

/* ----- /etc/krb5.conf --------------------------------------------- */

/*
 * krb5.conf presence + a quick "is there a default_realm?" check.
 *
 * We deliberately don't try to parse [libdefaults] -- libkrb5 itself
 * will do that at runtime, and any parse failure will surface as a
 * KRB5_ERR_KRB5_CONF_PARSE there.  This pre-flight just confirms the
 * file exists and contains the string "default_realm".
 */
static enum diag_verdict check_krb5_conf(void)
{
	static const char *paths[] = {
		"/etc/krb5.conf",
		"/etc/krb5/krb5.conf", /* some BSD-ish layouts */
		NULL,
	};

	const char *found = NULL;
	for (int i = 0; paths[i]; i++) {
		if (file_readable(paths[i])) {
			found = paths[i];
			break;
		}
	}

	if (!found) {
		diag_emit("krb5-conf", DIAG_FAIL,
			  "/etc/krb5.conf not found or not readable");
		return DIAG_FAIL;
	}

	/* Look for default_realm = anywhere in the file */
	FILE *fp = fopen(found, "re");
	if (!fp) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s: %s", found, strerror(errno));
		diag_emit("krb5-conf", DIAG_FAIL, buf);
		return DIAG_FAIL;
	}
	char line[512];
	int has_default_realm = 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "default_realm")) {
			has_default_realm = 1;
			break;
		}
	}
	fclose(fp);

	if (!has_default_realm) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "%s: no default_realm in [libdefaults]", found);
		diag_emit("krb5-conf", DIAG_FAIL, buf);
		return DIAG_FAIL;
	}
	diag_emit("krb5-conf", DIAG_PASS, found);
	return DIAG_PASS;
}

/* ----- /etc/krb5.keytab ------------------------------------------- */

/*
 * Keytab presence + readability + nfs/ principal check.
 *
 * We use `klist -k` rather than libkrb5 directly so this file does
 * not need to link libkrb5.  If `klist` is missing we degrade to a
 * stat()-only check and emit WARN, since the host may still be
 * functional via gssproxy.
 */
static enum diag_verdict check_keytab(void)
{
	static const char *path = "/etc/krb5.keytab";

	struct stat st;
	if (stat(path, &st) != 0) {
		diag_emit("keytab-file", DIAG_FAIL,
			  "/etc/krb5.keytab does not exist");
		return DIAG_FAIL;
	}
	if (!S_ISREG(st.st_mode)) {
		diag_emit("keytab-file", DIAG_FAIL,
			  "/etc/krb5.keytab is not a regular file");
		return DIAG_FAIL;
	}
	if (access(path, R_OK) != 0) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "%s: not readable by uid %u (perm %04o or SELinux)",
			 path, (unsigned)getuid(),
			 (unsigned)(st.st_mode & 07777));
		diag_emit("keytab-readable", DIAG_FAIL, buf);
		return DIAG_FAIL;
	}
	diag_emit("keytab-file", DIAG_PASS, path);

	/*
     * Look for an nfs/ principal.  klist -k prints lines like:
     *   2 nfs/host.example.com@REALM
     * We grep for "nfs/" in its output via a shell pipeline.
     */
	int rc = run_silent("klist -k /etc/krb5.keytab 2>/dev/null "
			    "| grep -q '[[:space:]]nfs/'");
	if (rc == -1) {
		diag_emit("keytab-nfs-principal", DIAG_WARN,
			  "system() failed; cannot inspect keytab contents");
		return DIAG_WARN;
	}
	if (rc == 127) {
		diag_emit("keytab-nfs-principal", DIAG_WARN,
			  "klist not installed; install krb5-workstation to "
			  "verify keytab contents");
		return DIAG_WARN;
	}
	if (rc != 0) {
		diag_emit("keytab-nfs-principal", DIAG_FAIL,
			  "no nfs/<host>@REALM principal in /etc/krb5.keytab");
		return DIAG_FAIL;
	}
	diag_emit("keytab-nfs-principal", DIAG_PASS,
		  "nfs/ principal present in keytab");
	return DIAG_PASS;
}

/* ----- User TGT (credential cache) -------------------------------- */

static enum diag_verdict check_user_tgt(void)
{
	/*
     * `klist -s` returns 0 iff there is at least one valid ticket
     * in the default credential cache.  No ticket isn't necessarily
     * a hard fail because rpc.gssd / gssproxy may use a machine
     * credential instead, so we report WARN rather than FAIL.
     */
	int rc = run_silent("klist -s 2>/dev/null");
	if (rc == -1) {
		diag_emit("user-tgt", DIAG_WARN, "system() failed");
		return DIAG_WARN;
	}
	if (rc == 127) {
		diag_emit("user-tgt", DIAG_WARN,
			  "klist not installed (cannot check user TGT)");
		return DIAG_WARN;
	}
	if (rc == 0) {
		diag_emit("user-tgt", DIAG_PASS,
			  "user has valid Kerberos credentials");
		return DIAG_PASS;
	}
	diag_emit("user-tgt", DIAG_WARN,
		  "no user TGT (run kinit if testing user-cred mounts)");
	return DIAG_WARN;
}

/* ----- gssproxy or rpc.gssd --------------------------------------- */

/*
 * Modern distros (RHEL 8+, Fedora, Ubuntu 20+) prefer gssproxy.
 * Older systems still use rpc.gssd.  Either is acceptable; both
 * missing is a failure.
 */
static enum diag_verdict check_gss_helper(void)
{
	int gssproxy = run_silent("pgrep -x gssproxy >/dev/null 2>&1");
	int rpcgssd = run_silent("pgrep -x rpc.gssd >/dev/null 2>&1");

	/* pgrep not installed: cannot decide. */
	if (gssproxy == 127 || rpcgssd == 127) {
		diag_emit(
			"gss-helper", DIAG_WARN,
			"pgrep not installed; cannot check gssproxy/rpc.gssd");
		return DIAG_WARN;
	}
	if (gssproxy == 0) {
		diag_emit("gss-helper", DIAG_PASS, "gssproxy is running");
		return DIAG_PASS;
	}
	if (rpcgssd == 0) {
		diag_emit("gss-helper", DIAG_PASS, "rpc.gssd is running");
		return DIAG_PASS;
	}
	diag_emit("gss-helper", DIAG_FAIL,
		  "neither gssproxy nor rpc.gssd is running "
		  "(systemctl enable --now gssproxy)");
	return DIAG_FAIL;
}

/* ----- nfsidmap --------------------------------------------------- */

static enum diag_verdict check_nfsidmap(void)
{
	static const char *paths[] = {
		"/usr/sbin/nfsidmap",
		"/usr/local/sbin/nfsidmap",
		"/sbin/nfsidmap",
		NULL,
	};
	for (int i = 0; paths[i]; i++) {
		if (access(paths[i], X_OK) == 0) {
			diag_emit("nfsidmap-installed", DIAG_PASS, paths[i]);
			return DIAG_PASS;
		}
	}
	diag_emit("nfsidmap-installed", DIAG_FAIL,
		  "nfsidmap not found (install nfs-utils)");
	return DIAG_FAIL;
}

/* ----- FQDN hostname ---------------------------------------------- */

/*
 * Kerberos service principals are derived from canonical FQDN
 * hostnames.  A short hostname here doesn't *guarantee* a runtime
 * failure (libkrb5 may canonicalize via DNS) but it's a reliable
 * source of "PRINCIPAL_FORM" mismatches in the wild.
 */
static enum diag_verdict check_hostname_fqdn(void)
{
	struct utsname un;
	if (uname(&un) != 0) {
		diag_emit("hostname-fqdn", DIAG_WARN, "uname() failed");
		return DIAG_WARN;
	}
	if (strchr(un.nodename, '.') == NULL) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "nodename '%s' is not a fully qualified domain name",
			 un.nodename);
		diag_emit("hostname-fqdn", DIAG_FAIL, buf);
		return DIAG_FAIL;
	}
	diag_emit("hostname-fqdn", DIAG_PASS, un.nodename);
	return DIAG_PASS;
}

/* ----- Forward + reverse DNS round-trip --------------------------- */

/*
 * Forward+reverse DNS sanity for the local hostname.  Done via
 * `getent hosts $(hostname)` followed by a reverse `getent hosts
 * <ip>`; if the reverse name doesn't match the forward name we
 * report RDNS_MISMATCH territory.  Best-effort: missing getent or
 * unusual NSS configurations report WARN, not FAIL.
 */
static enum diag_verdict check_rdns(void)
{
	int rc = run_silent(
		"set -e; "
		"name=$(hostname); "
		"ip=$(getent hosts \"$name\" | awk '{print $1; exit}'); "
		"test -n \"$ip\" || exit 2; "
		"rname=$(getent hosts \"$ip\" | awk '{print $2; exit}'); "
		"test -n \"$rname\" || exit 3; "
		"test \"$rname\" = \"$name\" >/dev/null 2>&1");

	if (rc == -1) {
		diag_emit("rdns", DIAG_WARN, "system() failed");
		return DIAG_WARN;
	}
	if (rc == 127) {
		diag_emit("rdns", DIAG_WARN,
			  "getent not installed (cannot check forward/reverse "
			  "DNS)");
		return DIAG_WARN;
	}
	if (rc == 2 || rc == 3) {
		diag_emit("rdns", DIAG_WARN,
			  "could not resolve local hostname forward/reverse");
		return DIAG_WARN;
	}
	if (rc == 0) {
		diag_emit("rdns", DIAG_PASS,
			  "forward and reverse DNS agree for local hostname");
		return DIAG_PASS;
	}
	diag_emit("rdns", DIAG_FAIL,
		  "forward and reverse DNS for local hostname disagree "
		  "(see RDNS_MISMATCH)");
	return DIAG_FAIL;
}

/* ----- Registration ----------------------------------------------- */

static const struct diag_check s_check_krb5_conf = {
	.name = "krb5-conf",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_krb5_conf,
};
static const struct diag_check s_check_keytab = {
	.name = "keytab",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_keytab,
};
static const struct diag_check s_check_user_tgt = {
	.name = "user-tgt",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_user_tgt,
};
static const struct diag_check s_check_gss_helper = {
	.name = "gss-helper",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_gss_helper,
};
static const struct diag_check s_check_nfsidmap = {
	.name = "nfsidmap-installed",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_nfsidmap,
};
static const struct diag_check s_check_hostname_fqdn = {
	.name = "hostname-fqdn",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_hostname_fqdn,
};
static const struct diag_check s_check_rdns = {
	.name = "rdns",
	.domains = DIAG_DOMAIN_KRB5,
	.run = check_rdns,
};

void diag_init_krb5(void)
{
	diag_register(&s_check_krb5_conf);
	diag_register(&s_check_keytab);
	diag_register(&s_check_user_tgt);
	diag_register(&s_check_gss_helper);
	diag_register(&s_check_nfsidmap);
	diag_register(&s_check_hostname_fqdn);
	diag_register(&s_check_rdns);
}
