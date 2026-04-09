#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# analyze_nfs_results.py -- parse and evaluate nfs-test-tools output
#
# Reads the ASCII output of nfs_tls_test or nfs_krb5_test, applies
# pass/fail thresholds, and prints a structured verdict.
#
# Exit codes:
#   0  PASS  -- all checks passed
#   1  FAIL  -- at least one FAIL finding
#   2  WARN  -- no FAILs but at least one WARN finding
#
# Usage:
#   ./src/nfs_tls_test --host SERVER ... 2>&1 | scripts/analyze_nfs_results.py
#   scripts/analyze_nfs_results.py results.txt
#   scripts/analyze_nfs_results.py --warn-handshake-p99 50 results.txt

import argparse
import re
import sys
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PhaseStats:
    p50: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    p999: float = 0.0
    avg: float = 0.0
    min: float = 0.0
    max: float = 0.0


@dataclass
class TlsResult:
    """Parsed output from nfs_tls_test."""
    header: str = ""
    tls_version: str = ""
    tls_cipher: str = ""
    tls_curve: str = ""
    sessions_resumed: int = 0
    sessions_full: int = 0
    conn_ok: int = 0
    conn_fail: int = 0
    phase: dict = field(default_factory=dict)  # phase name -> PhaseStats
    fail_tcp: int = 0
    fail_probe: int = 0
    fail_handshake: int = 0
    fail_rpc: int = 0
    samples_dropped: bool = False


@dataclass
class Krb5Result:
    """Parsed output from nfs_krb5_test."""
    header: str = ""
    context_established: bool = False
    null_calls_ok: int = 0
    null_calls_total: int = 0
    verdict: str = ""          # "PASS" or "FAIL"
    failure_line: str = ""     # verbatim error line
    failure_step: str = ""     # diagnosis key


@dataclass
class Finding:
    level: str      # "PASS", "WARN", or "FAIL"
    check: str
    message: str


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_tls(lines: list) -> Optional[TlsResult]:
    r = TlsResult()

    # Header: "nfs_tls_test: server:2049, ..."
    for line in lines:
        m = re.match(r'^nfs_tls_test:\s+(.+)', line)
        if m:
            r.header = m.group(1)
            break
    if not r.header:
        return None

    # TLS version/cipher/curve
    for line in lines:
        m = re.match(r'^TLS:\s+(\S+),\s+(\S+),\s+(\S+)', line)
        if m:
            r.tls_version = m.group(1)
            r.tls_cipher = m.group(2)
            r.tls_curve = m.group(3)

    # Sessions line: "Sessions: N resumed, M full handshake"
    for line in lines:
        m = re.match(r'^\s*Sessions:\s+(\d+)\s+resumed,\s+(\d+)\s+full', line)
        if m:
            r.sessions_resumed = int(m.group(1))
            r.sessions_full = int(m.group(2))

    # Total connections: "Total connections: 1000 ok, 0 fail"
    for line in lines:
        m = re.match(r'^\s*Total connections:\s+(\d+)\s+ok,\s+(\d+)\s+fail', line)
        if m:
            r.conn_ok = int(m.group(1))
            r.conn_fail = int(m.group(2))

    # Phase breakdown -- collect once we see the header row
    in_table = False
    for line in lines:
        if re.search(r'p50\s+p95\s+p99', line):
            in_table = True
            continue
        if in_table:
            # "  tcp           0.41    0.89    1.23     3.12    0.44    0.21    4.01"
            m = re.match(
                r'^\s+(\w+)\s+'
                r'([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
                line)
            if m:
                ps = PhaseStats(
                    p50=float(m.group(2)),
                    p95=float(m.group(3)),
                    p99=float(m.group(4)),
                    p999=float(m.group(5)),
                    avg=float(m.group(6)),
                    min=float(m.group(7)),
                    max=float(m.group(8)),
                )
                r.phase[m.group(1)] = ps
            elif line.strip() == "":
                in_table = False

    # Error breakdown: "Error breakdown: 0 tcp, 0 probe, 0 handshake, 0 rpc"
    for line in lines:
        m = re.match(
            r'^\s*Error breakdown:\s+'
            r'(\d+)\s+tcp,\s+(\d+)\s+probe,\s+(\d+)\s+handshake,\s+(\d+)\s+rpc',
            line)
        if m:
            r.fail_tcp = int(m.group(1))
            r.fail_probe = int(m.group(2))
            r.fail_handshake = int(m.group(3))
            r.fail_rpc = int(m.group(4))

    # Sample overflow warning
    for line in lines:
        if 'samples dropped' in line.lower() or 'overflow' in line.lower():
            r.samples_dropped = True

    return r


def parse_krb5(lines: list) -> Optional[Krb5Result]:
    r = Krb5Result()

    # Header: "nfs_krb5_test: server:2049 ..."
    for line in lines:
        m = re.match(r'^nfs_krb5_test:\s+(.+)', line)
        if m:
            r.header = m.group(1)
            break
    if not r.header:
        return None

    for line in lines:
        line = line.rstrip()

        if 'RPCSEC_GSS context established' in line:
            r.context_established = True

        # "NULL call 2/5 OK"
        m = re.match(r'^\s*NULL call\s+(\d+)/(\d+)\s+OK', line)
        if m:
            r.null_calls_ok = int(m.group(1))
            r.null_calls_total = int(m.group(2))

        if line.strip() == 'PASS':
            r.verdict = 'PASS'
        elif line.strip() == 'FAIL':
            r.verdict = 'FAIL'

        # Capture the failure line (first error-looking line)
        if not r.failure_line and r.verdict != 'PASS':
            if re.search(r'error|failed|refused|denied|maj=|FAIL', line, re.I):
                r.failure_line = line

    # Diagnose failure step from presence/absence of expected lines
    all_text = "\n".join(lines)
    if r.verdict == 'FAIL':
        if 'connect:' in all_text and 'refused' in all_text.lower():
            r.failure_step = 'tcp_connect'
        elif 'gss_import_name' not in all_text:
            r.failure_step = 'gss_import_name'
        elif 'gss_init_sec_context' in all_text and 'context established' not in all_text:
            r.failure_step = 'gss_init_sec_context'
        elif r.context_established and r.null_calls_ok < r.null_calls_total:
            r.failure_step = 'null_call'
        else:
            r.failure_step = 'unknown'

    return r


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

@dataclass
class Thresholds:
    warn_tls_version: str = "TLSv1.3"
    warn_tcp_p99_ms: float = 10.0
    fail_tcp_p99_ms: float = 50.0
    warn_handshake_p99_ms: float = 100.0
    fail_handshake_p99_ms: float = 500.0
    warn_total_p99_ms: float = 200.0
    fail_total_p99_ms: float = 1000.0
    warn_max_to_p999_ratio: float = 10.0
    warn_session_reuse_pct: float = 50.0


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_tls(r: TlsResult, th: Thresholds) -> list:
    findings = []

    def add(level, check, msg):
        findings.append(Finding(level, check, msg))

    # Connection errors
    if r.conn_fail > 0:
        pct = 100.0 * r.conn_fail / (r.conn_ok + r.conn_fail) if (r.conn_ok + r.conn_fail) > 0 else 100.0
        add('FAIL', 'error_count',
            f"{r.conn_fail} connection failure(s) ({pct:.1f}%): "
            f"tcp={r.fail_tcp}, probe={r.fail_probe}, "
            f"handshake={r.fail_handshake}, rpc={r.fail_rpc}")
    else:
        add('PASS', 'error_count',
            f"All {r.conn_ok} connection(s) succeeded")

    # Phase-specific error breakdown
    phase_fails = {
        'tcp': (r.fail_tcp, 'server unreachable or accept queue full'),
        'probe': (r.fail_probe, 'server AUTH_TLS (RFC 9289) implementation error'),
        'handshake': (r.fail_handshake, 'TLS cert mismatch, expired cert, or ALPN missing "sunrpc"'),
        'rpc': (r.fail_rpc, 'NFS stack not responding after TLS establishment'),
    }
    for phase, (count, cause) in phase_fails.items():
        if count > 0:
            add('FAIL', f'phase_{phase}',
                f"{count} {phase} failure(s): {cause}")

    # TLS version
    if r.tls_version:
        if r.tls_version != th.warn_tls_version:
            add('WARN', 'tls_version',
                f"Negotiated {r.tls_version} (expected {th.warn_tls_version}); "
                f"cipher={r.tls_cipher}")
        else:
            add('PASS', 'tls_version',
                f"{r.tls_version}, {r.tls_cipher}, {r.tls_curve}")
    else:
        add('WARN', 'tls_version',
            "TLS version not reported (was --tls-info passed?)")

    # Session reuse
    total_sessions = r.sessions_resumed + r.sessions_full
    if total_sessions > 0:
        reuse_pct = 100.0 * r.sessions_resumed / total_sessions
        if r.sessions_full > 0 and reuse_pct < th.warn_session_reuse_pct:
            add('WARN', 'session_reuse',
                f"Session reuse rate {reuse_pct:.1f}% "
                f"({r.sessions_resumed} resumed, {r.sessions_full} full); "
                f"server session cache may be misconfigured")
        else:
            add('PASS', 'session_reuse',
                f"{reuse_pct:.1f}% reuse "
                f"({r.sessions_resumed} resumed, {r.sessions_full} full)")
    elif r.sessions_resumed == 0 and r.sessions_full == 0:
        add('WARN', 'session_reuse',
            "Session stats not reported (was --tls-info passed?)")

    # Phase latency thresholds
    latency_checks = [
        ('tcp',       'warn_tcp_p99_ms',       'fail_tcp_p99_ms'),
        ('handshake', 'warn_handshake_p99_ms', 'fail_handshake_p99_ms'),
        ('total',     'warn_total_p99_ms',      'fail_total_p99_ms'),
    ]
    for phase, warn_attr, fail_attr in latency_checks:
        ps = r.phase.get(phase)
        if not ps:
            continue
        warn_val = getattr(th, warn_attr)
        fail_val = getattr(th, fail_attr)
        if ps.p99 > fail_val:
            add('FAIL', f'latency_{phase}_p99',
                f"{phase} p99={ps.p99:.1f}ms (threshold {fail_val:.0f}ms); "
                f"p50={ps.p50:.2f}ms, max={ps.max:.1f}ms")
        elif ps.p99 > warn_val:
            add('WARN', f'latency_{phase}_p99',
                f"{phase} p99={ps.p99:.1f}ms (warning threshold {warn_val:.0f}ms); "
                f"p50={ps.p50:.2f}ms, max={ps.max:.1f}ms")
        else:
            add('PASS', f'latency_{phase}_p99',
                f"{phase} p99={ps.p99:.2f}ms")

    # Outlier detection: max >> p99.9
    total_ps = r.phase.get('total')
    if total_ps and total_ps.p999 > 0:
        ratio = total_ps.max / total_ps.p999
        if ratio > th.warn_max_to_p999_ratio:
            add('WARN', 'latency_outlier',
                f"max={total_ps.max:.1f}ms is {ratio:.1f}x p99.9={total_ps.p999:.1f}ms; "
                f"single severe outlier (scheduling jitter, TCP retransmit)")

    # Sample overflow
    if r.samples_dropped:
        add('WARN', 'samples_dropped',
            "Some samples were dropped (sample array overflow); "
            "reduce --iterations or increase --threads to avoid")

    return findings


def analyze_krb5(r: Krb5Result) -> list:
    findings = []

    def add(level, check, msg):
        findings.append(Finding(level, check, msg))

    if r.verdict == 'PASS':
        add('PASS', 'verdict', 'RPCSEC_GSS context established and all NULL calls succeeded')
        if r.null_calls_total > 0:
            add('PASS', 'null_calls',
                f"{r.null_calls_ok}/{r.null_calls_total} authenticated NULL call(s) OK")
        return findings

    # FAIL path
    step_causes = {
        'tcp_connect':         'Server not reachable: wrong host/port, firewall, or server down',
        'gss_import_name':     'Invalid --principal syntax; use "nfs/hostname@REALM" or "nfs@hostname"',
        'gss_init_sec_context': (
            'Kerberos failure: no TGT (run kinit), wrong realm, keytab expired, '
            'clock skew > 5 min, or wrong SPN on server'
        ),
        'null_call':           'GSS context established but NULL call failed; check server NFS stack',
        'unknown':             'Unknown failure; run with --verbose to see GSS token exchange',
    }

    cause = step_causes.get(r.failure_step, 'Unknown cause')
    add('FAIL', 'verdict',
        f"Failed at step '{r.failure_step}': {cause}")

    if r.failure_line:
        add('FAIL', 'failure_line',
            f"Error output: {r.failure_line.strip()}")

    if not r.context_established:
        add('FAIL', 'context',
            'RPCSEC_GSS context was never established')

    return findings


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(tool: str, header: str, findings: list):
    print(f"\n{'='*60}")
    print(f"Tool:    {tool}")
    print(f"Target:  {header}")
    print(f"{'='*60}")

    worst = 'PASS'
    for f in findings:
        if f.level == 'FAIL':
            worst = 'FAIL'
        elif f.level == 'WARN' and worst == 'PASS':
            worst = 'WARN'

    print(f"\nVerdict: {worst}\n")

    for f in findings:
        if f.level == 'PASS':
            marker = '[PASS]'
        elif f.level == 'WARN':
            marker = '[WARN]'
        else:
            marker = '[FAIL]'
        print(f"  {marker:<8} {f.check}: {f.message}")

    print()
    return worst


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='Analyze nfs_tls_test or nfs_krb5_test output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  PASS  all checks passed
  1  FAIL  at least one FAIL finding
  2  WARN  no FAILs but at least one WARN

Examples:
  # Pipe directly from the tool
  ./src/nfs_tls_test --host SERVER --threads 4 --tls-info 2>&1 | %(prog)s

  # Analyze a saved file
  %(prog)s results.txt

  # Loosen handshake threshold for a cross-datacenter run
  %(prog)s --warn-handshake-p99 150 --fail-handshake-p99 800 results.txt
""")
    p.add_argument('file', nargs='?',
                   help='Input file (default: stdin)')
    p.add_argument('--warn-tcp-p99',       type=float, default=10.0,
                   metavar='MS', help='WARN threshold for tcp p99 (ms, default 10)')
    p.add_argument('--fail-tcp-p99',       type=float, default=50.0,
                   metavar='MS', help='FAIL threshold for tcp p99 (ms, default 50)')
    p.add_argument('--warn-handshake-p99', type=float, default=100.0,
                   metavar='MS', help='WARN threshold for handshake p99 (ms, default 100)')
    p.add_argument('--fail-handshake-p99', type=float, default=500.0,
                   metavar='MS', help='FAIL threshold for handshake p99 (ms, default 500)')
    p.add_argument('--warn-total-p99',     type=float, default=200.0,
                   metavar='MS', help='WARN threshold for total p99 (ms, default 200)')
    p.add_argument('--fail-total-p99',     type=float, default=1000.0,
                   metavar='MS', help='FAIL threshold for total p99 (ms, default 1000)')
    p.add_argument('--warn-session-reuse', type=float, default=50.0,
                   metavar='PCT', help='WARN if session reuse below PCT%% (default 50)')
    return p


def main():
    args = build_parser().parse_args()

    if args.file:
        try:
            with open(args.file) as fh:
                text = fh.read()
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        text = sys.stdin.read()

    lines = text.splitlines()

    th = Thresholds(
        warn_tcp_p99_ms=args.warn_tcp_p99,
        fail_tcp_p99_ms=args.fail_tcp_p99,
        warn_handshake_p99_ms=args.warn_handshake_p99,
        fail_handshake_p99_ms=args.fail_handshake_p99,
        warn_total_p99_ms=args.warn_total_p99,
        fail_total_p99_ms=args.fail_total_p99,
        warn_session_reuse_pct=args.warn_session_reuse,
    )

    # Auto-detect tool from output
    tls_result = parse_tls(lines)
    krb5_result = parse_krb5(lines)

    verdicts = []

    if tls_result:
        findings = analyze_tls(tls_result, th)
        v = print_report('nfs_tls_test', tls_result.header, findings)
        verdicts.append(v)

    if krb5_result:
        findings = analyze_krb5(krb5_result)
        v = print_report('nfs_krb5_test', krb5_result.header, findings)
        verdicts.append(v)

    if not verdicts:
        print("error: could not detect nfs_tls_test or nfs_krb5_test output",
              file=sys.stderr)
        print("  Expected header line starting with 'nfs_tls_test:' or 'nfs_krb5_test:'",
              file=sys.stderr)
        sys.exit(1)

    if 'FAIL' in verdicts:
        sys.exit(1)
    if 'WARN' in verdicts:
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()
