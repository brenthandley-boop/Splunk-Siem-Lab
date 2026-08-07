# Threat Detection Lab — Adversarial Kill Chain Simulation & Real-Time SIEM Response

[![Splunk](https://img.shields.io/badge/Splunk_Enterprise-9.4.3-FF5733?style=flat-square&logo=splunk&logoColor=white)](https://www.splunk.com)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-2024-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-6_Techniques_Mapped-E03C31?style=flat-square)](https://attack.mitre.org)
[![Kill Chain](https://img.shields.io/badge/Kill_Chain-Recon_→_Containment-7B2FBE?style=flat-square)](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
[![SOC Ready](https://img.shields.io/badge/SOC_Skills-Tier_1_Ready-00A86B?style=flat-square)]()
[![Status](https://img.shields.io/badge/Project-Complete-brightgreen?style=flat-square)]()

---

> **6 kill chain phases. 4 attack tools. 7 custom Splunk detections. 1 complete IR playbook.**
> Built from scratch by a 6-person SOC team with no prior enterprise security experience.
> Every alert, every detection rule, every dashboard panel, and every recommendation in this repo
> was written against real attack telemetry — not simulated data, not textbook examples.

---

| Lab Detail | Value |
|---|---|
| **SIEM Platform** | Splunk Enterprise 9.4.3 |
| **Attacker Host** | Kali Linux — 10.0.2.5 |
| **Target Host** | Windows Server 2022 — 10.0.2.15 |
| **Attack Tools** | netdiscover · nmap · Hydra · xfreerdp |
| **Log Pipeline** | Windows Security Events via Universal Forwarder 9.4.0 → port 9997 |
| **Event Codes Monitored** | 4624 · 4625 · 5156 · 5157 · 5158 · 4720 · 4728 |
| **MITRE Techniques** | T1595.001 · T1046 · T1110.001 · T1078 · T1136.001 · T1562.004 |
| **Alerts Built** | 7 custom Splunk alerts with tuned SPL logic |
| **Team** | The Spelunker-People — Fullstack Academy Cybersecurity Bootcamp, April 2026 |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Lab Architecture](#2-lab-architecture)
3. [Cyber Kill Chain — Full Simulation](#3-cyber-kill-chain--full-simulation)
4. [Attack Walkthroughs](#4-attack-walkthroughs)
   - [Phase 1 — Passive Reconnaissance (netdiscover)](#phase-1--passive-reconnaissance-netdiscover)
   - [Phase 2 — Active Scanning (nmap)](#phase-2--active-scanning-nmap)
   - [Phase 3 — Credential Brute Force (Hydra RDP)](#phase-3--credential-brute-force-hydra-rdp)
   - [Phase 4 — Post-Exploitation Access (xfreerdp)](#phase-4--post-exploitation-access-xfreerdp)
5. [Splunk Detection Logic](#5-splunk-detection-logic)
6. [Dashboard & Visualizations](#6-dashboard--visualizations)
7. [Incident Response Playbook](#7-incident-response-playbook)
8. [Indicators of Compromise (IOCs)](#8-indicators-of-compromise-iocs)
9. [False Positive Analysis](#9-false-positive-analysis)
10. [Defensive Recommendations](#10-defensive-recommendations)
11. [Lessons Learned](#11-lessons-learned)
12. [Team & Roles](#12-team--roles)
13. [References & Framework Mappings](#13-references--framework-mappings)

---

## 1. Executive Summary

This project simulates a complete adversarial intrusion lifecycle against an isolated Windows Server 2022 target, monitored in real time by Splunk Enterprise 9.4.3. Beginning with passive host discovery and progressing through port scanning, RDP credential brute-force, and authenticated post-exploitation access, the simulation covers the full Lockheed Martin Cyber Kill Chain from reconnaissance through containment.

All six kill chain phases are mapped to specific MITRE ATT&CK techniques. Seven custom Splunk detection rules were authored, tuned, and validated against live attack telemetry. A Tier 1 and Tier 2 Incident Response playbook was produced in professional SOC analyst format, alongside an Indicators of Compromise table and formal defensive recommendations memo.

The lab demonstrates core SOC L1 competencies: log ingestion pipeline configuration, Windows Security Event analysis, behavioral detection rule authorship, SIEM dashboard construction, and structured incident response documentation.

---

## 2. Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Isolated VirtualBox Network                  │
│                                                                  │
│   ┌─────────────────────┐          ┌─────────────────────────┐  │
│   │   KALI LINUX         │          │   WINDOWS SERVER 2022   │  │
│   │   10.0.2.5           │          │   10.0.2.15             │  │
│   │                      │          │                         │  │
│   │  ┌────────────────┐  │ ATTACKS  │  ┌───────────────────┐  │  │
│   │  │ Splunk Ent.    │  │ ───────► │  │ RDP Port 3389     │  │  │
│   │  │ 9.4.3 :8000    │  │          │  └───────────────────┘  │  │
│   │  └────────────────┘  │          │                         │  │
│   │                      │          │  ┌───────────────────┐  │  │
│   │  ┌────────────────┐  │◄─────────│  │ Universal Fwd     │  │  │
│   │  │ Port 9997      │  │  LOGS    │  │ 9.4.0 :9997       │  │  │
│   │  │ (receiver)     │  │          │  └───────────────────┘  │  │
│   │  └────────────────┘  │          │                         │  │
│   │                      │          │  ┌───────────────────┐  │  │
│   │  Attack Tools:       │          │  │ Windows Firewall  │  │  │
│   │  netdiscover         │          │  │ EventLog Security │  │  │
│   │  nmap                │          │  │ 4624/4625         │  │  │
│   │  Hydra               │          │  │ 5156/5157/5158    │  │  │
│   │  xfreerdp            │          │  └───────────────────┘  │  │
│   └─────────────────────┘          └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Log flow:** Windows Security Events → Universal Forwarder → port 9997 → Splunk `main` index → SPL detection rules → triggered alerts → dashboard panels

**Key configuration file:** `inputs.conf` on the Windows host controls exactly which event logs the Forwarder ships. Without `[WinEventLog://Security]` stanza with `index = main`, the pipeline produces no data regardless of network connectivity.

---

## 3. Cyber Kill Chain — Full Simulation

| Phase | Tool | What Happened | Windows EventCode | MITRE Technique |
|---|---|---|---|---|
| **1 — Reconnaissance** | `netdiscover` | ARP sweep of 10.0.2.0/24 — confirmed Windows host at 10.0.2.15 | 5156 · 5157 | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) |
| **2 — Scanning** | `nmap -sS -T4 -p-` | SYN scan of all 65,535 ports — confirmed RDP (3389/tcp) open, OS fingerprinted as Windows Server 2022 | 5156 · 5157 · 5158 | [T1046](https://attack.mitre.org/techniques/T1046/) |
| **3 — Exploitation** | `Hydra` | Automated RDP brute force using 60-entry password list against Administrator — Password.1!! found on attempt ~127 | 4625 (×58) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| **4 — Installation** | `xfreerdp` | Authenticated RDP session opened as Administrator (Logon Type 10) — full GUI access established | 4624 | [T1078](https://attack.mitre.org/techniques/T1078/) |
| **5 — Detection** | `Splunk` | Real-time alerts fired on port scan, brute force threshold, and post-brute success — full attack chain visible in dashboard | SPL custom rules | TA0043 · TA0006 |
| **6 — Response** | `Windows Firewall` | Inbound block rule created targeting 10.0.2.5 across all profiles — continued EventCode 5157 events confirmed attacker IP is being dropped | 5157 (post-block) | [T1562.004](https://attack.mitre.org/techniques/T1562/004/) |

---

## 4. Attack Walkthroughs

### Phase 1 — Passive Reconnaissance (netdiscover)

**Objective:** Identify live hosts on the network without triggering active connection logs.

```bash
sudo netdiscover -r 10.0.2.0/24 -P
```

**What it does:** Sends ARP requests across the subnet. ARP operates at Layer 2 — it doesn't generate Windows authentication events. The result is a table of live IPs and their MAC addresses with vendor identification.

**Lab result:**
```
IP            At MAC Address     Count   Len  MAC Vendor / Hostname
10.0.2.15     08:00:27:ba:97:95    1      60  PCS Systemtechnik GmbH (VirtualBox NIC)
```

**Why it matters defensively:** ARP-based recon often goes undetected without dedicated network monitoring. In this lab, Windows Filtering Platform auditing enabled visibility into the subsequent scan activity (EventCode 5157), but the ARP sweep itself generates no Windows Security log entries. In production, network-layer visibility (via NetFlow, NDR, or IDS) would be required to catch this phase.

**Splunk visibility:** Indirect — the ARP sweep itself does not appear in Windows Security logs. The subsequent nmap scan does.

---

### Phase 2 — Active Scanning (nmap)

**Objective:** Map open ports and identify attack surface on the confirmed target.

```bash
sudo nmap -sS -T4 -p- 10.0.2.15
```

**Flag breakdown:**
- `-sS` — SYN scan: sends TCP SYN packets, reads SYN-ACK responses without completing the handshake. Faster and lower-noise than a full connect scan.
- `-T4` — Aggressive timing: maximizes scan speed, creating a visible spike in Windows Filtering Platform events.
- `-p-` — All 65,535 ports scanned (not just the common top-1000).

**Lab result:** Scan completed in ~91 seconds. Two open ports confirmed:
```
PORT     STATE  SERVICE
3389/tcp open   ms-wbt-server    ← RDP confirmed
5985/tcp open   wsman
```

**Windows Filtering Platform events generated:**
- `EventCode 5156` — allowed connection (open ports responding with SYN-ACK)
- `EventCode 5157` — blocked connection (closed ports returning RST)
- `EventCode 5158` — port bind events

> **Note:** These events only appear because Windows Filtering Platform auditing was enabled with:
> `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable`
> Without this one command, nmap scans are completely invisible to Splunk.

**SPL to confirm in Splunk:**
```splunk
index=main sourcetype="WinEventLog:Security" (EventCode=5156 OR EventCode=5157 OR EventCode=5158)
| stats count by EventCode, src_ip
| sort - count
```

---

### Phase 3 — Credential Brute Force (Hydra RDP)

**Objective:** Obtain valid credentials for the Administrator account via automated password guessing.

```bash
hydra -l Administrator -P ~/passwords.txt -t 4 -V rdp://10.0.2.15
```

**Flag breakdown:**
- `-l Administrator` — single username target
- `-P ~/passwords.txt` — 60-entry password wordlist (common passwords + lab-specific entries)
- `-t 4` — 4 parallel attack threads
- `-V` — verbose output showing each attempt in the terminal

**What Windows logs:** Every failed RDP login attempt generates `EventCode 4625` with:
- `Logon Type: 3` (Network) or `10` (Remote Interactive)
- `Failure Reason: Unknown user name or bad password`
- `Authentication Package: NTLM`
- `Source Network Address: 10.0.2.5` ← attacker IP

**Lab result:** Password `Password.1!!` found at approximately attempt 127 of 192. Before success, 58 EventCode 4625 entries were generated in the Splunk index from source IP 10.0.2.5.

**Why the timing matters:** Hydra with `-t 4` generates multiple attempts per second. The 58 failures in rapid succession from a single IP is the exact behavioral pattern the brute force detection alert targets — not the content of any individual failure, but the velocity and volume from one source.

---

### Phase 4 — Post-Exploitation Access (xfreerdp)

**Objective:** Use the compromised credentials to establish a live authenticated session on the target host.

```bash
xfreerdp /u:Administrator /p:'Password.1!!' /v:10.0.2.15
```

**What it does:** Opens a full Remote Desktop session as Administrator. A complete Windows desktop renders on the Kali screen. The attacker now has GUI-level access identical to a local admin sitting at the physical machine.

**What Windows logs:** A single `EventCode 4624` (Successful Logon) with:
- `Logon Type: 10` (RemoteInteractive — specifically RDP)
- `Authentication Package: NTLM`
- `Source Network Address: 10.0.2.5` ← Kali IP
- `Account Name: Administrator`

**Why this is the hardest event to detect in isolation:** A single 4624 from a valid Administrator account is indistinguishable from a legitimate admin login. The detection logic that matters here is *context* — the same IP that generated 58 x EventCode 4625 just generated a 4624. Without correlating those two event types across the same source IP and time window, the successful login looks completely normal.

**This is the exact scenario Alert 3 catches** — and the centerpiece of the IR playbook.

---

## 5. Splunk Detection Logic

> All SPL queries were tested against live attack telemetry. Comments explain each clause.

### Alert 1 — Failed Login Threshold (Baseline Brute Force)

**Severity:** High | **Trigger:** 5+ EventCode 4625 from one IP within 5 seconds

```splunk
index=main EventCode=4625              /* failed logon events only */
| bucket _time span=5s                 /* group into 5-second time windows */
| stats count as fail_count            /* count failures per window */
    by src_ip, _time                   /* grouped by source IP and window */
| where fail_count >= 5                /* threshold: 5+ = automated attack pattern */
```

**False positive scenario:** A user's keyboard autorepeat fires multiple password attempts. Mitigation: add `NOT src_ip IN ("known-admin-workstations")` and raise threshold to 10 during business hours.

---

### Alert 2 — Port Scan Detected

**Severity:** High | **Trigger:** One IP contacts 20+ unique destination ports within 60 seconds

```splunk
index=main (EventCode=5156 OR EventCode=5157)   /* firewall allow/block events */
| stats dc(dest_port) as unique_ports            /* count distinct destination ports */
    by src_ip                                    /* per source IP */
| where unique_ports > 20                        /* 20+ unique ports = scan pattern */
| sort - unique_ports                            /* highest scanner first */
```

**Prerequisite:** Windows Filtering Platform auditing must be enabled on the target host (`auditpol` command).

---

### Alert 3 — Brute Force Success (Critical)

**Severity:** High | **Trigger:** IP with 3+ failures has at least one success

```splunk
index=main EventCode=4625                         /* start with failures */
| stats count as fail_count by src_ip            /* count failures per IP */
| where fail_count >= 3                          /* threshold: 3+ failures */
| join type=inner src_ip                         /* correlate with successes */
    [search index=main EventCode=4624            /* successful logon events */
     | stats count by src_ip]                    /* same IP must have a success */
| table src_ip, fail_count                       /* output: attacker IP + failure count */
```

**Why this alert is the most valuable:** Any IP that failed 3+ times and then succeeded is the exact behavioral fingerprint of a brute force that worked. This is what a SOC L1 escalates immediately — not the individual failures, but the success that follows them.

---

### Alert 4 — New Admin Account Created

**Severity:** High | **Trigger:** EventCode 4720 (account created) or 4728 (added to privileged group)

```splunk
index=main (EventCode=4720 OR EventCode=4728)    /* account creation/modification events */
| eval event_type=case(                          /* human-readable label */
    EventCode=4720, "Account Created",
    EventCode=4728, "Added to Privileged Group"
  )
| table _time, event_type, user, src_user, host  /* analyst-ready output */
```

---

### Alert 5 — Off-Hours Login Activity

**Severity:** Medium | **Trigger:** Successful login before 08:00 or after 20:00

```splunk
index=main EventCode=4624                            /* successful logins */
| eval hour=tonumber(strftime(_time, "%H"))          /* extract hour of day (UTC) */
| where hour < 8 OR hour > 20                        /* outside business hours */
| table _time, user, src_ip, host, hour              /* analyst output */
```

---

### Alert 6 — Password Spraying

**Severity:** Low | **Trigger:** One IP targets 5+ unique usernames with failures

```splunk
index=main EventCode=4625                                  /* failed logins */
| stats dc(user) as unique_users,                          /* count unique usernames */
        count as total_attempts by src_ip                  /* and total attempts per IP */
| where unique_users >= 5                                  /* 5+ accounts = spray pattern */
| sort - unique_users
| table src_ip, unique_users, total_attempts
```

**Why this differs from brute force:** Brute force = one account, many passwords. Spraying = many accounts, one password. Spray attacks evade account lockout policies that would trigger on a single account.

---

### Alert 7 — Outbound Traffic Spike (Exfiltration Signal)

**Severity:** Medium | **Trigger:** Single host transmits >50MB outbound in one session

```splunk
index=main
| stats sum(bytes_out) as total_bytes_out by src_ip, host  /* sum outbound bytes per host */
| where total_bytes_out > 50000000                         /* 50MB threshold */
| eval MB_sent=round(total_bytes_out/1048576, 2)           /* convert to readable MB */
| table src_ip, host, MB_sent
| sort - MB_sent
```

---

## 6. Dashboard & Visualizations

**Dashboard name:** `SOC Lab — Threat Monitoring`

**Panel layout (top to bottom):**

| Row | Panels | Purpose |
|---|---|---|
| Row 1 | 3 single-value tiles — Total Alerts · Active Hosts · Unique Attacking IPs | Executive glance — first thing a manager sees |
| Row 2 | Bar chart (failed vs successful logins) + Line chart (events over time) | Attack volume visualization |
| Row 3 | Top attacking IPs table + Alert severity donut chart | Threat actor identification + triage depth |
| Row 4 | Activity by hour column chart + Login origin map | Temporal anomaly + geographic context |
| Row 5 | Attack chain timeline — full width | Complete incident reconstruction |

**Screenshots:** See `/screenshots/` directory organized by phase.

---

## 7. Incident Response Playbook

See [`IR-PLAYBOOK.md`](./IR-PLAYBOOK.md) for the complete dual-tier playbook.

The playbook is authored in two formats:
- **Tier 1 SOC Analyst** — initial alert triage, validation, and containment actions within the first 15 minutes
- **Tier 2 SOC Analyst** — deep forensic investigation, root cause analysis, threat hunt, and full remediation

---

## 8. Indicators of Compromise (IOCs)

See [`IOC-REPORT.md`](./IOC-REPORT.md) for the full formatted IOC table.

**Summary table:**

| IOC Type | Value | Context |
|---|---|---|
| Source IP | `10.0.2.5` | Kali Linux attacker — origin of all attack traffic |
| Target IP | `10.0.2.15` | Windows Server 2022 victim host |
| Username targeted | `Administrator` | Local admin account — brute-forced via RDP |
| Protocol | RDP (TCP/3389) | Remote Desktop Protocol — attack vector |
| Authentication package | NTLM | Used during RDP authentication attempts |
| Logon Type | `10` (RemoteInteractive) | RDP-specific logon — distinguishes from local logins |
| Failure reason code | `0xC000006A` | Unknown username or bad password |
| Sub-status code | `0xC0000064` | User does not exist (returned for wrong username) |
| Tool signature — nmap | SYN packets to 65,535 ports in ~91 seconds | Creates EventCode 5157 spike |
| Tool signature — Hydra | Rapid-succession 4625 events, same src_ip, Logon Type 3 | ~4 attempts/second cadence |
| EventCode sequence | 5156/5157 → 4625×N → 4624 | Full kill chain signature in chronological order |

---

## 9. False Positive Analysis

Understanding what benign activity could trigger each alert — and how to tune rules to reduce noise without losing signal — is a core SOC analyst skill.

| Alert | Benign Scenario That Could Trigger It | Tuning Recommendation |
|---|---|---|
| Failed login threshold (5 in 5s) | User with keyboard autorepeat holds backspace on a lock screen | Raise threshold to 10 during 08:00–18:00. Add workstation allowlist for known IT admin hosts. |
| Port scan detection | Network monitoring tool or vulnerability scanner running on schedule | Whitelist known internal scanner IPs. Reduce sensitivity from 20 ports to 50 for internal sources. |
| Brute force success | IT admin using a password manager that retries on timeout | Add filter for known admin source IPs. Require both fail count threshold AND a minimum time delta. |
| New admin account created | Scheduled IT onboarding process | Create a change-window exclusion: suppress alert if EventCode 4720 occurs Mon–Fri 09:00–17:00 AND matches approved-users list. |
| Off-hours login | On-call engineer responding to an incident at 2am | Maintain an on-call roster and cross-reference user field against it before escalating. |
| Password spraying | User testing multiple username variations while locked out | Threshold of 5 unique users is conservative. In production, raise to 10+ with a minimum 30-minute window. |

---

## 10. Defensive Recommendations

*Authored in the format of a security advisory memo. Each recommendation includes rationale, implementation complexity, and expected risk reduction.*

---

**Recommendation 1: Enforce Multi-Factor Authentication on All RDP Sessions**

The entirety of this attack chain is terminated by successful RDP credential compromise. A second authentication factor renders the Hydra brute force attack ineffective regardless of password strength or list length. Even if credentials are obtained through other means (phishing, credential stuffing), MFA prevents their use via RDP.

*Implementation:* Microsoft Entra ID conditional access policy, Duo Security RDP Gateway, or Windows Hello for Business. *Complexity:* Low–Medium. *Risk reduction:* Critical.

---

**Recommendation 2: Implement Account Lockout Policy**

The default Windows Server configuration in this lab had no account lockout threshold. Setting a lockout policy (recommended: 5 failed attempts → 30-minute lockout) would have terminated the Hydra attack after the first 5 attempts, long before the password was found.

*Implementation:* Group Policy Object — `Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy`. *Complexity:* Low. *Risk reduction:* High.

---

**Recommendation 3: Restrict RDP Access to Authorized Source IPs Only**

RDP exposed to any source IP on the network is unnecessary attack surface. In this lab, Kali could reach port 3389 without restriction. A Windows Firewall inbound rule limiting RDP access to specific management IPs would have prevented Hydra from reaching the service entirely.

*Implementation:* Windows Defender Firewall Advanced Security → Inbound Rules → RDP (3389) → Scope → Remote IP → specific admin subnets only. *Complexity:* Low. *Risk reduction:* High.

---

**Recommendation 4: Replace NTLM with Kerberos Authentication**

All Hydra authentication attempts in this lab used NTLM (visible in EventCode 4625 field: `Authentication Package: NTLM`). NTLM is susceptible to relay attacks and pass-the-hash in addition to brute force. Enforcing Kerberos for all domain authentication eliminates this attack surface.

*Implementation:* Group Policy — `Security Settings → Local Policies → Security Options → Network security: Restrict NTLM`. *Complexity:* Medium (requires domain environment). *Risk reduction:* High.

---

**Recommendation 5: Implement Splunk Forwarder Health Monitoring**

During this project, the Universal Forwarder silently stopped shipping logs on two occasions. In a production environment, this means a blind spot in SIEM coverage — attacks could occur during the gap. Splunk's internal `_introspection` index contains forwarder health data; alerting on a forwarder that stops checking in is a standard SOC hygiene practice.

*Implementation:* Splunk alert on `index=_internal sourcetype=splunkd | stats max(_time) as last_seen by host | where (now()-last_seen) > 300`. *Complexity:* Low. *Risk reduction:* Operational.

---

## 11. Lessons Learned

*Written with professional candor — what broke, what we didn't understand, and what we'd do differently in a production environment.*

**1. The inputs.conf failure is invisible if you don't know where to look.**
The Universal Forwarder can be running as a service, showing green in the Services panel, and still shipping zero data — because without `inputs.conf`, it has no instruction on what to monitor. The diagnostic that finally revealed this was checking `splunkd.log` for `WinEventLog` entries: if there's no stanza acknowledgment, the file either doesn't exist or has a syntax error. In production, we'd configure the Splunk Deployment Server to push and enforce inputs.conf centrally rather than relying on manual file creation.

**2. Port 9997 disappears on Kali restart.**
The `splunk enable listen 9997` command doesn't survive a Kali reboot by default. Every time Kali was restarted during this project, the receiving port was gone and the forwarder had nowhere to send data. The fix is `splunk enable boot-start` combined with the listen command — in production, a systemd service unit would guarantee the port is re-enabled on every boot.

**3. The off-hours alert was UTC, not local time.**
When we first built Alert 5, it fired on logins at completely unexpected times. Splunk's `strftime` operates in UTC by default. Our lab VMs were in Eastern Time (UTC-4). The alert was triggering "off-hours" logins at what was actually 10am local time. The fix was adjusting the hour thresholds by the timezone offset. In production, always configure Splunk's server timezone and align all timestamps before building time-based detections.

**4. Alert 3 (brute force success) requires data to exist before it can be tested.**
The join-based SPL query for "success after failures" returns nothing if you haven't run an attack first. We wasted time debugging the query syntax when the real issue was that there was no matching data in the index yet. Build alerts in sequence: run the attack, verify raw events exist in Splunk, then build the alert on top of confirmed data.

**5. Logon Type 10 is the RDP fingerprint, not just EventCode 4624.**
Early in the project, Alert 3 was catching all successful logins — including local console logins, service logons, and scheduled tasks — because it searched broadly on EventCode 4624. Adding `Logon_Type=10` narrowed it specifically to Remote Interactive (RDP) sessions. This is the kind of precision that separates a noisy alert from an actionable one.

---

## 12. Team & Roles

| Name | Role | Contribution |
|---|---|---|
| **Jeremy Lemmel** | Project Lead & Detection Engineer | Project architecture, Splunk alert authorship, overall coordination |
| **Luc Van Houten** | Infrastructure Engineer | VirtualBox lab setup, Universal Forwarder configuration, network topology |
| **Fadi Nasrallah** | Red Team Operator | Attack simulation design and execution — netdiscover, nmap, Hydra |
| **Brent Handley** | Blue Team Analyst | Splunk dashboard build, visualization design, alert tuning |
| **Austin Perey** | Incident Response Analyst | IR playbook authorship, incident report, firewall containment |
| **Alison Liang** | Technical Writer & Presenter | Documentation, presentation design, video production |

**Individual contributor repositories:**

- [Jeremy Lemmel](https://github.com/JeremyLemmel/Cybersecurity-Capstone-Bruteforce-Detection)
- [Fadi Nasrallah](https://github.com/FadiNasrallah1/Threat-Detection-using-Splunk)
- [Alison Liang](https://github.com/alisonliang17/splunk-siem-lab)
- [Austin Perey](https://github.com/austinjoep/splunk-siem-lab)
- [Luc Van Houten](https://github.com/Lucvhc/splunk-siem-lab)

---

## 13. References & Framework Mappings

| Resource | Link |
|---|---|
| MITRE ATT&CK Framework | https://attack.mitre.org |
| T1595.001 — Active Scanning | https://attack.mitre.org/techniques/T1595/001/ |
| T1046 — Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |
| T1110.001 — Brute Force: Password Guessing | https://attack.mitre.org/techniques/T1110/001/ |
| T1078 — Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| T1136.001 — Create Account: Local Account | https://attack.mitre.org/techniques/T1136/001/ |
| Lockheed Martin Cyber Kill Chain | https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html |
| Splunk Enterprise Documentation | https://docs.splunk.com/Documentation/Splunk |
| Windows Security Event Log Reference | https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview |
| Fullstack Academy Cybersecurity Bootcamp | https://www.fullstackacademy.com/programs/cybersecurity-bootcamp |

---

*Fullstack Academy Cybersecurity Bootcamp — The Spelunker-People — April 2026*
*This project was completed in an isolated lab environment. All attack simulations were conducted against systems owned and controlled by the team.*
