# 🔐 SSH Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Educational-orange?style=flat-square)
![Domain](https://img.shields.io/badge/Domain-SOC%20%7C%20Blue%20Team-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)

> A Python-based log analysis tool that parses Linux `auth.log` files, detects brute-force SSH attacks, flags suspicious IPs, identifies possible account compromises, and generates structured security reports — core skills for **SOC L1 Analyst** and **Incident Response** roles.

---

## 📌 What This Tool Does

| Feature | Description |
|--------|-------------|
| **Brute-Force Detection** | Flags IPs exceeding configurable failed-attempt thresholds |
| **Distributed Attack Detection** | Identifies credential stuffing across multiple source IPs |
| **Compromise Detection** | Flags successful logins from IPs that previously failed |
| **Privileged Account Monitoring** | Alerts on root/admin/ubuntu targeted attacks |
| **Break-In Detection** | Parses kernel-level `POSSIBLE BREAK-IN ATTEMPT` flags |
| **Sudo Command Audit** | Extracts all privilege escalation events |
| **IOC Export** | Generates firewall-ready IP blocklists |
| **JSON / CSV Reports** | Structured output for SIEM ingestion or ticketing |
| **Sample Log Generator** | Built-in realistic test data — no real server needed |
| **Gzip Log Support** | Reads compressed `.gz` log archives directly |

---

## 🛡️ Disclaimer

> This tool is for **educational purposes and authorised security analysis only.**  
> Only analyze logs from systems you own or have explicit written permission to investigate.  
> The author assumes no responsibility for misuse.

---

## 🚀 Quick Start

### No installation needed (stdlib only)

```bash
git clone https://github.com/Jatin-pardeshi/log-analyzer.git
cd log-analyzer

# Generate sample log and run analysis immediately
python log_analyzer.py --generate-sample
```

That's it — no pip install required. The tool uses Python's standard library only.

---

## 💻 Usage

```bash
python log_analyzer.py [logfile] [options]
```

### Examples

```bash
# Generate a realistic sample log and analyze it
python log_analyzer.py --generate-sample

# Analyze a real system auth.log (Linux)
python log_analyzer.py /var/log/auth.log

# Analyze a compressed log archive
python log_analyzer.py /var/log/auth.log.1.gz

# Save full JSON report
python log_analyzer.py /var/log/auth.log -o report.json

# Export attacker IPs as CSV (for spreadsheet / ticketing)
python log_analyzer.py /var/log/auth.log --csv attackers.csv

# Export IOC list for firewall / SIEM import
python log_analyzer.py /var/log/auth.log --ioc blocklist.txt

# All exports in one command
python log_analyzer.py /var/log/auth.log -o report.json --csv attackers.csv --ioc ioc.txt

# Show only top 5 IPs (less noisy output)
python log_analyzer.py sample_auth.log --top 5
```

### All Options

```
positional arguments:
  logfile               Path to auth.log file (plain text or .gz)

optional arguments:
  --generate-sample     Generate a sample auth.log and analyze it
  -o, --output FILE     Save full JSON report
  --csv FILE            Save attacker IP list to CSV
  --ioc FILE            Export IOC list (firewall-ready IP blocklist)
  --top N               Number of top IPs/usernames to show (default: 10)
  --no-banner           Suppress ASCII banner
```

---

## 📊 Sample Output

```
══════════════════════════════════════════════════════════════════════
  LOG ANALYSIS REPORT
══════════════════════════════════════════════════════════════════════

  Total lines parsed:                       63
  Failed login attempts:                    55
  Successful logins:                         2
  Unique attacking IPs:                     11
  Brute-force IPs detected:                  2
  Possible compromises:                      1
  Break-in attempt flags:                    1
  Sudo commands logged:                      1

  ─── SECURITY ALERTS ──────────────────────────────────────────────
  [CRITICAL]   POSSIBLE_COMPROMISE    Successful login for 'ubuntu' after 35 failures
  [CRITICAL]   BREAK_IN_ATTEMPT       Kernel flagged POSSIBLE BREAK-IN at Jan 15 11:45:00
  [HIGH]       BRUTE_FORCE            35 failed attempts, 1 username(s) tried
  [HIGH]       DISTRIBUTED_ATTACK     User 'root' targeted from 8 IPs (8 total attempts)

  ─── TOP ATTACKING IPs ────────────────────────────────────────────
  IP ADDRESS         ATTEMPTS  USERNAMES TRIED
  ──────────────────────────────────────────────────────────────────
  192.168.1.100            35  root                  ◄ BRUTE FORCE
  10.0.0.55                20  admin0, admin1 ...    ◄ BRUTE FORCE
  172.16.1.2                1  root
  ...

  ─── MOST TARGETED USERNAMES ──────────────────────────────────────
  USERNAME              ATTEMPTS    SOURCE IPs  NOTE
  ──────────────────────────────────────────────────────────────────
  root                        43            9  PRIVILEGED ACCOUNT
  admin0                       1            1
  ...
```

---

## 📁 Project Structure

```
log-analyzer/
├── log_analyzer.py     # Main analyzer — parse, detect, report, export
├── sample_auth.log     # Generated test log (after running --generate-sample)
└── README.md           # This file
```

---

## 🧠 Security Concepts Demonstrated

This project reinforces the following real-world SOC analyst skills:

| Concept | Implementation |
|--------|----------------|
| **Log Parsing** | Regex-based extraction from raw `auth.log` format |
| **Threat Detection** | Threshold-based brute-force and anomaly detection |
| **Incident Triage** | Severity classification: CRITICAL → HIGH → MEDIUM |
| **IOC Generation** | Producing structured attacker IP lists for blocking |
| **Credential Stuffing ID** | Detecting distributed attacks across multiple IPs |
| **Post-Compromise Analysis** | Flagging successful logins after failure patterns |
| **Privilege Escalation Audit** | Sudo command extraction and logging |
| **SIEM Thinking** | Structured JSON output designed for SIEM ingestion |

---

## 🔍 Threat Detection Logic

```
auth.log lines
     │
     ▼
  Regex Parser ──→ Events by category
  (failed, accepted, invalid_user,
   breakin, sudo, pam_failure)
     │
     ▼
  Threat Analyzer
  ├── Count failures per IP
  ├── Count failures per username
  ├── Identify brute-force IPs (≥10 attempts)
  ├── Detect distributed attacks (≥5 source IPs per user)
  ├── Flag privileged account attacks (root, admin, ubuntu…)
  ├── Detect successful login AFTER failures → POSSIBLE COMPROMISE
  └── Parse kernel break-in flags
     │
     ▼
  Severity Scoring → CRITICAL / HIGH / MEDIUM
     │
     ├── Terminal Report (coloured)
     ├── JSON Report (structured)
     ├── CSV Export (spreadsheet)
     └── IOC List (firewall blocklist)
```

---

## 🌱 What I'm Working On Next

- [ ] Windows Event Log (`.evtx`) support
- [ ] GeoIP lookup — map attacker IPs to countries
- [ ] Timeline view — visualise attack patterns by hour
- [ ] Slack/webhook alerting for real-time notifications
- [ ] MITRE ATT&CK mapping (T1110 — Brute Force)

---

## 📚 Related Learning

This project complements my work on:
- **TryHackMe** — Top 25% global ranking | Completed: Defensive Security Intro, SOC Level 1 path | [Profile](https://tryhackme.com/p/Coderjatin)
- **CEH v13** — EC-Council Certified Ethical Hacker (in progress)
- **Related rooms**: Splunk, Log Analysis, Threat Intelligence, DFIR

---

## 🔗 My Other Security Projects

| Project | Description |
|--------|-------------|
| [network-scanner](https://github.com/Jatin-pardeshi/network-scanner) | TCP port scanner with nmap integration and risk flagging |
| [log-analyzer](https://github.com/Jatin-pardeshi/log-analyzer) | This project |

---

## 👤 Author

**Jatin Pardeshi**  
Cybersecurity Student | SOC Analyst & Threat Hunting Enthusiast | CEH v13 Candidate  
📍 Pune, India

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Jatin%20Pardeshi-blue?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/jatin-pardeshi-3a6994347/)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Coderjatin-red?style=flat-square)](https://tryhackme.com/p/Coderjatin)
[![GitHub](https://img.shields.io/badge/GitHub-Jatin--pardeshi-black?style=flat-square&logo=github)](https://github.com/Jatin-pardeshi)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
