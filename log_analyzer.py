#!/usr/bin/env python3
"""
log_analyzer.py
---------------
A Python-based log analysis tool that parses Linux auth.log / syslog files,
detects failed SSH login attempts, identifies brute-force patterns, flags
suspicious IPs, and generates structured security reports.

Author : Jatin Pardeshi (github.com/Jatin-pardeshi)
Purpose: Educational — demonstrates log parsing, threat detection, and
         incident triage skills core to SOC L1 analyst work.
Usage  : python log_analyzer.py --help
"""

import re
import sys
import json
import csv
import os
import argparse
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

# ─────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────
USE_COLOR = sys.platform != "win32" and sys.stdout.isatty()

def c(code, text): return f"\033[{code}m{text}\033[0m" if USE_COLOR else text
RED    = lambda t: c("91", t)
GREEN  = lambda t: c("92", t)
YELLOW = lambda t: c("93", t)
CYAN   = lambda t: c("96", t)
BOLD   = lambda t: c("1",  t)
DIM    = lambda t: c("2",  t)
MAGENTA= lambda t: c("95", t)

# ─────────────────────────────────────────────
# Regex patterns for auth.log parsing
# ─────────────────────────────────────────────
PATTERNS = {
    # Failed password attempt
    "failed_password": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:"
        r".*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    # Invalid user attempt
    "invalid_user": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:"
        r".*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    # Successful login
    "accepted_password": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:"
        r".*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    # Connection closed
    "disconnected": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*Disconnected from (?:invalid user )?(?P<user>\S+)? ?(?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    # Too many auth failures
    "too_many_failures": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*error: maximum authentication attempts exceeded.*from (?P<ip>[\d.]+)"
    ),
    # POSSIBLE BREAK-IN attempt
    "breakin_attempt": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*POSSIBLE BREAK-IN ATTEMPT.*from (?P<ip>[\d.]+)"
    ),
    # sudo usage
    "sudo_usage": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+sudo.*:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)"
    ),
    # PAM authentication failure
    "pam_failure": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*pam_unix.*authentication failure.*user=(?P<user>\S+)"
    ),
}

# Thresholds for threat classification
THRESHOLDS = {
    "brute_force":        10,   # failed attempts to be classified as brute force
    "distributed_attack": 5,    # min IPs targeting same user = distributed attack
    "high_risk_user":     3,    # attempts on root/admin = high risk
}

BANNER = r"""
  _                           _                _
 | |    ___   __ _    /\   /\/_\  _ __   __ _| |_   _ _______ _ __
 | |   / _ \ / _` |   \ \ / ///_\| '_ \ / _` | | | | |_  / _ \ '__|
 | |__| (_) | (_| |    \ V //  _  \ | | | (_| | | |_| |/ /  __/ |
 |_____\___/ \__, |     \_/ \_/ \_/_| |_|\__,_|_|\__, /___\___|_|
             |___/                               |___/

  by Jatin Pardeshi  |  github.com/Jatin-pardeshi  |  SOC Analysis Tool
"""

# ─────────────────────────────────────────────────────────
# Log parser
# ─────────────────────────────────────────────────────────

def parse_log(filepath: str) -> dict:
    """
    Parse an auth.log file and extract all security-relevant events.
    Returns a structured dict of events grouped by category.
    """
    results = {
        "failed_logins":      [],   # list of {ip, user, time, host}
        "successful_logins":  [],
        "invalid_users":      [],
        "too_many_failures":  [],
        "breakin_attempts":   [],
        "sudo_commands":      [],
        "pam_failures":       [],
        "parse_errors":       0,
        "total_lines":        0,
    }

    path = Path(filepath)
    if not path.exists():
        print(RED(f"[ERROR] File not found: {filepath}"))
        sys.exit(1)

    # Handle gzip-compressed logs (auth.log.1.gz etc.)
    if filepath.endswith(".gz"):
        import gzip
        opener = lambda f: gzip.open(f, "rt", errors="ignore")
    else:
        opener = lambda f: open(f, "r", errors="ignore")

    with opener(filepath) as fh:
        for line in fh:
            results["total_lines"] += 1
            line = line.rstrip()

            matched = False

            # ── Failed password ─────────────────────────
            m = PATTERNS["failed_password"].search(line)
            if m:
                results["failed_logins"].append({
                    "ip":    m.group("ip"),
                    "user":  m.group("user"),
                    "time":  f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "host":  m.group("host"),
                    "port":  m.group("port"),
                    "raw":   line,
                })
                matched = True

            # ── Invalid user ────────────────────────────
            m = PATTERNS["invalid_user"].search(line)
            if m and not matched:
                results["invalid_users"].append({
                    "ip":   m.group("ip"),
                    "user": m.group("user"),
                    "time": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "raw":  line,
                })
                matched = True

            # ── Accepted login ──────────────────────────
            m = PATTERNS["accepted_password"].search(line)
            if m and not matched:
                results["successful_logins"].append({
                    "ip":   m.group("ip"),
                    "user": m.group("user"),
                    "time": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "host": m.group("host"),
                    "raw":  line,
                })
                matched = True

            # ── Too many failures ───────────────────────
            m = PATTERNS["too_many_failures"].search(line)
            if m and not matched:
                results["too_many_failures"].append({
                    "ip":   m.group("ip"),
                    "time": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "raw":  line,
                })
                matched = True

            # ── Possible break-in ───────────────────────
            m = PATTERNS["breakin_attempt"].search(line)
            if m and not matched:
                results["breakin_attempts"].append({
                    "ip":   m.group("ip"),
                    "time": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "raw":  line,
                })

            # ── Sudo commands ───────────────────────────
            m = PATTERNS["sudo_usage"].search(line)
            if m:
                results["sudo_commands"].append({
                    "user":    m.group("user"),
                    "command": m.group("command").strip(),
                    "time":    f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "raw":     line,
                })

            # ── PAM failures ─────────────────────────────
            m = PATTERNS["pam_failure"].search(line)
            if m and not matched:
                results["pam_failures"].append({
                    "user": m.group("user"),
                    "time": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "raw":  line,
                })

    return results


# ─────────────────────────────────────────────────────────
# Threat analysis engine
# ─────────────────────────────────────────────────────────

def analyze_threats(parsed: dict) -> dict:
    """
    Run threat detection logic over parsed log data.
    Identifies brute-force attackers, targeted users, and suspicious IPs.
    """
    threats = {
        "ip_failed_counts":    Counter(),   # IP → total failed attempts
        "ip_usernames":        defaultdict(set),  # IP → set of usernames tried
        "user_failed_counts":  Counter(),   # username → total attempts
        "user_source_ips":     defaultdict(set),  # username → source IPs
        "brute_force_ips":     [],          # IPs exceeding threshold
        "distributed_attacks": [],          # users targeted by many IPs
        "root_attacks":        [],          # attempts on privileged accounts
        "successful_after_fail": [],        # successful login from IP that also failed
        "alerts":              [],          # high-severity alerts
    }

    failed   = parsed["failed_logins"] + parsed["invalid_users"]
    success  = parsed["successful_logins"]

    # Count failures per IP and per username
    for event in failed:
        ip   = event["ip"]
        user = event["user"]
        threats["ip_failed_counts"][ip] += 1
        threats["ip_usernames"][ip].add(user)
        threats["user_failed_counts"][user] += 1
        threats["user_source_ips"][user].add(ip)

    # Identify brute-force IPs
    for ip, count in threats["ip_failed_counts"].items():
        if count >= THRESHOLDS["brute_force"]:
            threats["brute_force_ips"].append({
                "ip":             ip,
                "failed_attempts": count,
                "usernames_tried": sorted(threats["ip_usernames"][ip]),
                "unique_usernames": len(threats["ip_usernames"][ip]),
            })

    threats["brute_force_ips"].sort(key=lambda x: x["failed_attempts"], reverse=True)

    # Identify distributed attacks (one user targeted by many IPs)
    for user, ips in threats["user_source_ips"].items():
        if len(ips) >= THRESHOLDS["distributed_attack"]:
            threats["distributed_attacks"].append({
                "username":    user,
                "source_ips":  sorted(ips),
                "ip_count":    len(ips),
                "total_attempts": threats["user_failed_counts"][user],
            })

    threats["distributed_attacks"].sort(key=lambda x: x["ip_count"], reverse=True)

    # Root / privileged account attacks
    privileged = {"root", "admin", "administrator", "ubuntu", "ec2-user", "pi"}
    for user, count in threats["user_failed_counts"].items():
        if user.lower() in privileged and count >= THRESHOLDS["high_risk_user"]:
            threats["root_attacks"].append({
                "username": user,
                "attempts": count,
                "source_ips": sorted(threats["user_source_ips"][user]),
            })

    # Successful login from an IP that also had failures (possible successful breach)
    failed_ips  = set(threats["ip_failed_counts"].keys())
    success_ips = {e["ip"] for e in success}
    overlap     = failed_ips & success_ips

    for event in success:
        if event["ip"] in overlap:
            prior_fails = threats["ip_failed_counts"][event["ip"]]
            threats["successful_after_fail"].append({
                "ip":            event["ip"],
                "user":          event["user"],
                "time":          event["time"],
                "prior_failures": prior_fails,
            })

    # Generate high-severity alerts
    for entry in threats["brute_force_ips"]:
        threats["alerts"].append({
            "severity": "HIGH",
            "type":     "BRUTE_FORCE",
            "ip":       entry["ip"],
            "detail":   f"{entry['failed_attempts']} failed attempts, {entry['unique_usernames']} username(s) tried",
        })

    for entry in threats["successful_after_fail"]:
        threats["alerts"].append({
            "severity": "CRITICAL",
            "type":     "POSSIBLE_COMPROMISE",
            "ip":       entry["ip"],
            "detail":   f"Successful login for '{entry['user']}' after {entry['prior_failures']} failures",
        })

    for entry in threats["distributed_attacks"]:
        threats["alerts"].append({
            "severity": "HIGH",
            "type":     "DISTRIBUTED_ATTACK",
            "ip":       "multiple",
            "detail":   f"User '{entry['username']}' targeted from {entry['ip_count']} IPs ({entry['total_attempts']} total attempts)",
        })

    for entry in parsed["breakin_attempts"]:
        threats["alerts"].append({
            "severity": "CRITICAL",
            "type":     "BREAK_IN_ATTEMPT",
            "ip":       entry["ip"],
            "detail":   f"Kernel flagged POSSIBLE BREAK-IN at {entry['time']}",
        })

    # Sort alerts: CRITICAL first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threats["alerts"].sort(key=lambda x: severity_order.get(x["severity"], 4))

    return threats


# ─────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────

def print_report(parsed: dict, threats: dict, top_n: int = 10) -> None:
    """Pretty-print the full analysis report to terminal."""

    print()
    print(BOLD("═" * 70))
    print(BOLD("  LOG ANALYSIS REPORT"))
    print(BOLD("═" * 70))

    # ── Summary stats ──────────────────────────────
    total_failed  = len(parsed["failed_logins"]) + len(parsed["invalid_users"])
    total_success = len(parsed["successful_logins"])
    unique_ips    = len(threats["ip_failed_counts"])

    print(f"\n  {'Total lines parsed:':<35} {parsed['total_lines']:>8,}")
    print(f"  {'Failed login attempts:':<35} {RED(str(total_failed)):>17}")
    print(f"  {'Successful logins:':<35} {GREEN(str(total_success)):>17}")
    print(f"  {'Unique attacking IPs:':<35} {YELLOW(str(unique_ips)):>17}")
    print(f"  {'Brute-force IPs detected:':<35} {RED(str(len(threats['brute_force_ips']))):>17}")
    print(f"  {'Possible compromises:':<35} {RED(str(len(threats['successful_after_fail']))):>17}")
    print(f"  {'Break-in attempt flags:':<35} {RED(str(len(parsed['breakin_attempts']))):>17}")
    print(f"  {'Sudo commands logged:':<35} {YELLOW(str(len(parsed['sudo_commands']))):>17}")

    # ── Alerts ──────────────────────────────────────
    if threats["alerts"]:
        print(f"\n{BOLD('  ─── SECURITY ALERTS ──────────────────────────────────────────────')}")
        for alert in threats["alerts"]:
            sev = alert["severity"]
            sev_label = RED(f"[{sev}]") if sev == "CRITICAL" else YELLOW(f"[{sev}]")
            print(f"  {sev_label:<22} {CYAN(alert['type']):<28} {alert['detail']}")
    else:
        print(GREEN("\n  [+] No high-severity threats detected."))

    # ── Top attacking IPs ─────────────────────────────
    print(f"\n{BOLD('  ─── TOP ATTACKING IPs ─────────────────────────────────────────────')}")
    print(f"  {'IP ADDRESS':<18} {'ATTEMPTS':>10}  {'USERNAMES TRIED'}")
    print("  " + "─" * 60)
    for ip, count in threats["ip_failed_counts"].most_common(top_n):
        users = ", ".join(sorted(threats["ip_usernames"][ip])[:5])
        if len(threats["ip_usernames"][ip]) > 5:
            users += f" (+{len(threats['ip_usernames'][ip]) - 5} more)"
        flag = RED(" ◄ BRUTE FORCE") if count >= THRESHOLDS["brute_force"] else ""
        print(f"  {ip:<18} {count:>10}  {DIM(users)}{flag}")

    # ── Most targeted usernames ───────────────────────
    print(f"\n{BOLD('  ─── MOST TARGETED USERNAMES ───────────────────────────────────────')}")
    print(f"  {'USERNAME':<20} {'ATTEMPTS':>10}  {'SOURCE IPs':>12}  NOTE")
    print("  " + "─" * 60)
    privileged = {"root", "admin", "administrator", "ubuntu", "ec2-user", "pi"}
    for user, count in threats["user_failed_counts"].most_common(top_n):
        ip_count = len(threats["user_source_ips"][user])
        note = RED("PRIVILEGED ACCOUNT") if user.lower() in privileged else ""
        print(f"  {user:<20} {count:>10}  {ip_count:>12}  {note}")

    # ── Successful logins ─────────────────────────────
    if parsed["successful_logins"]:
        print(f"\n{BOLD('  ─── SUCCESSFUL LOGINS ─────────────────────────────────────────────')}")
        print(f"  {'TIME':<22} {'USER':<15} {'IP':<18} NOTE")
        print("  " + "─" * 65)
        for ev in parsed["successful_logins"]:
            note = RED("⚠ AFTER FAILURES") if ev["ip"] in threats["ip_failed_counts"] else ""
            print(f"  {ev['time']:<22} {ev['user']:<15} {ev['ip']:<18} {note}")

    # ── Distributed attacks ───────────────────────────
    if threats["distributed_attacks"]:
        print(f"\n{BOLD('  ─── DISTRIBUTED ATTACKS ───────────────────────────────────────────')}")
        for da in threats["distributed_attacks"]:
            print(f"  User {CYAN(da['username'])!s:<30} targeted from {RED(str(da['ip_count']))} IPs  "
                  f"({da['total_attempts']} total attempts)")

    # ── Sudo audit ────────────────────────────────────
    if parsed["sudo_commands"]:
        print(f"\n{BOLD('  ─── SUDO COMMAND AUDIT ────────────────────────────────────────────')}")
        for cmd in parsed["sudo_commands"][:10]:
            print(f"  {DIM(cmd['time']):<24} {YELLOW(cmd['user']):<15} {cmd['command'][:60]}")

    print(f"\n{BOLD('═' * 70)}")
    print(f"  Analysis complete — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(BOLD("═" * 70))
    print()


# ─────────────────────────────────────────────────────────
# Export functions
# ─────────────────────────────────────────────────────────

def export_json(parsed: dict, threats: dict, outfile: str) -> None:
    """Export full analysis to a structured JSON file."""
    payload = {
        "report_generated": datetime.now().isoformat(),
        "summary": {
            "total_lines":        parsed["total_lines"],
            "failed_attempts":    len(parsed["failed_logins"]) + len(parsed["invalid_users"]),
            "successful_logins":  len(parsed["successful_logins"]),
            "unique_attacker_ips": len(threats["ip_failed_counts"]),
            "brute_force_ips":    len(threats["brute_force_ips"]),
            "possible_compromises": len(threats["successful_after_fail"]),
        },
        "alerts":              threats["alerts"],
        "brute_force_ips":     threats["brute_force_ips"],
        "distributed_attacks": threats["distributed_attacks"],
        "root_attacks":        threats["root_attacks"],
        "successful_after_fail": threats["successful_after_fail"],
        "top_attacking_ips": [
            {
                "ip": ip,
                "failed_attempts": count,
                "usernames_tried": sorted(threats["ip_usernames"][ip]),
            }
            for ip, count in threats["ip_failed_counts"].most_common(20)
        ],
        "successful_logins":   parsed["successful_logins"],
        "sudo_commands":       parsed["sudo_commands"],
    }
    with open(outfile, "w") as f:
        json.dump(payload, f, indent=2)
    print(GREEN(f"\n  [+] JSON report saved → {outfile}"))


def export_csv(threats: dict, outfile: str) -> None:
    """Export top attacking IPs to CSV for SIEM ingestion / ticketing."""
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["ip", "failed_attempts", "unique_usernames", "usernames_tried"]
        )
        writer.writeheader()
        for ip, count in threats["ip_failed_counts"].most_common():
            writer.writerow({
                "ip":               ip,
                "failed_attempts":  count,
                "unique_usernames": len(threats["ip_usernames"][ip]),
                "usernames_tried":  "|".join(sorted(threats["ip_usernames"][ip])),
            })
    print(GREEN(f"  [+] CSV report saved → {outfile}"))


def export_ioc(threats: dict, outfile: str) -> None:
    """
    Export Indicators of Compromise — one IP per line.
    Ready to import directly into a firewall blocklist or SIEM watchlist.
    """
    with open(outfile, "w") as f:
        f.write(f"# IOC List — generated {datetime.now().isoformat()}\n")
        f.write(f"# Source: SSH auth.log analysis\n")
        f.write(f"# Format: IP,failed_attempts,threat_type\n\n")
        for entry in threats["brute_force_ips"]:
            f.write(f"{entry['ip']},{entry['failed_attempts']},BRUTE_FORCE\n")
        for entry in threats["successful_after_fail"]:
            f.write(f"{entry['ip']},{entry['prior_failures']},POSSIBLE_COMPROMISE\n")
    print(GREEN(f"  [+] IOC list saved → {outfile}"))


# ─────────────────────────────────────────────────────────
# Sample log generator (for demo / testing)
# ─────────────────────────────────────────────────────────

def generate_sample_log(outfile: str = "sample_auth.log") -> None:
    """
    Generate a realistic sample auth.log for testing and demonstration.
    Includes brute-force attempts, invalid users, a successful login,
    and privileged account attacks.
    """
    entries = [
        # — Brute-force from 192.168.1.100 —
        *[f"Jan {15+i//20} {8+i//60:02d}:{i%60:02d}:00 server1 sshd[1000]: Failed password for root from 192.168.1.100 port 4{i:04d} ssh2"
          for i in range(35)],
        # — Invalid user attempts from scanner —
        *[f"Jan 15 09:{i:02d}:00 server1 sshd[1001]: Invalid user admin{i} from 10.0.0.55"
          for i in range(20)],
        # — Distributed attack on root from multiple IPs —
        *[f"Jan 15 10:{i:02d}:00 server1 sshd[1002]: Failed password for root from 172.16.{i}.{i+1} port 22 ssh2"
          for i in range(8)],
        # — Successful login from attacker IP —
        "Jan 15 11:00:00 server1 sshd[1003]: Accepted password for ubuntu from 192.168.1.100 port 52000 ssh2",
        # — Legitimate successful login —
        "Jan 15 08:00:00 server1 sshd[999]: Accepted publickey for jatin from 10.10.10.5 port 43200 ssh2",
        # — Too many authentication failures —
        "Jan 15 11:30:00 server1 sshd[1004]: error: maximum authentication attempts exceeded for root from 203.0.113.50 port 22 ssh2 [preauth]",
        # — POSSIBLE BREAK-IN —
        "Jan 15 11:45:00 server1 sshd[1005]: Address 203.0.113.50 maps to attacker.example.com, but this does not map back to the address -- POSSIBLE BREAK-IN ATTEMPT!",
        # — Sudo usage —
        "Jan 15 12:00:00 server1 sudo:    ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        # — PAM failure —
        "Jan 15 12:10:00 server1 sshd[1006]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.1  user=root",
    ]

    with open(outfile, "w") as f:
        f.write("\n".join(entries) + "\n")

    print(GREEN(f"  [+] Sample log generated → {outfile}  ({len(entries)} lines)"))


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="SSH Auth Log Analyzer — detect brute-force, flag suspicious IPs, generate reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a sample log and analyze it (great for demo)
  python log_analyzer.py --generate-sample
  python log_analyzer.py sample_auth.log

  # Analyze a real auth.log
  python log_analyzer.py /var/log/auth.log

  # Export full JSON report
  python log_analyzer.py /var/log/auth.log -o report.json

  # Export IOC list for firewall import
  python log_analyzer.py /var/log/auth.log --ioc ioc_list.txt

  # Export CSV + JSON
  python log_analyzer.py /var/log/auth.log -o report.json --csv attackers.csv

  # Show only top 5 IPs
  python log_analyzer.py sample_auth.log --top 5
        """,
    )
    p.add_argument("logfile", nargs="?", default=None,
                   help="Path to auth.log file (or .gz compressed log)")
    p.add_argument("--generate-sample", action="store_true",
                   help="Generate a sample auth.log and analyze it")
    p.add_argument("-o", "--output",
                   help="Save full JSON report to this file")
    p.add_argument("--csv",
                   help="Save attacker IP list to CSV file")
    p.add_argument("--ioc",
                   help="Export IOC (Indicators of Compromise) list to file")
    p.add_argument("--top", type=int, default=10,
                   help="Number of top IPs/usernames to display (default: 10)")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress ASCII banner")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print(CYAN(BANNER))

    # Generate sample log if requested
    if args.generate_sample:
        sample_path = "sample_auth.log"
        generate_sample_log(sample_path)
        if not args.logfile:
            args.logfile = sample_path

    if not args.logfile:
        parser.print_help()
        sys.exit(0)

    print(BOLD(f"\n  Analyzing: {args.logfile}"))
    print(DIM( f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))

    # Parse
    parsed  = parse_log(args.logfile)

    # Analyze
    threats = analyze_threats(parsed)

    # Print report
    print_report(parsed, threats, top_n=args.top)

    # Exports
    if args.output:
        export_json(parsed, threats, args.output)
    if args.csv:
        export_csv(threats, args.csv)
    if args.ioc:
        export_ioc(threats, args.ioc)

    # Exit code: non-zero if critical alerts found (useful for CI/CD pipelines)
    critical = [a for a in threats["alerts"] if a["severity"] == "CRITICAL"]
    if critical:
        sys.exit(2)


if __name__ == "__main__":
    main()
