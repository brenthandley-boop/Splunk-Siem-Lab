# Threat Detection Lab — Adversarial Kill Chain Simulation & Real-Time SIEM Response

[![Splunk](https://img.shields.io/badge/Splunk_Enterprise-9.4.3-FF5733?style=flat-square&logo=splunk&logoColor=white)](https://www.splunk.com)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-2024-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-6_Techniques_Mapped-E03C31?style=flat-square)](https://attack.mitre.org)
[![Kill Chain](https://img.shields.io/badge/Kill_Chain-LM_7_Phase_Mapped-7B2FBE?style=flat-square)](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
[![SOC Ready](https://img.shields.io/badge/SOC_Skills-Tier_1_Ready-00A86B?style=flat-square)]()
[![Status](https://img.shields.io/badge/Project-Complete-brightgreen?style=flat-square)]()

---

> **7 kill chain phases. 4 attack tools. 7 custom Splunk detections — 5 validated live, 2 authored for coverage. 1 complete IR playbook.**
> Built from scratch by a 6-person SOC team with no prior enterprise security experience.
> Every alert, every detection rule, every dashboard panel, and every recommendation in this repo
> was written against real attack telemetry — not simulated data, not textbook examples.

---

| Lab Detail | Value |
|---|---|
| **SIEM Platform** | Splunk Enterprise 9.4.3 |
| **Attacker Host** | Kali Linux — `ATTACKER_IP` |
| **Target Host** | Windows Server 2022 — `VICTIM_IP` |
| **Attack Tools** | netdiscover · nmap · Hydra · xfreerdp |
| **Log Pipeline** | Windows Security Events via Universal Forwarder 9.4.0 → port 9997 |
| **Event Codes Monitored** | 4624 · 4625 · 5156 · 5157 · 5158 · 4720 · 4728 |
| **MITRE Techniques** | T1595.001 · T1046 · T1110.001 · T1078 · T1136.001 · T1562.004 |
| **Alerts Built** | 7 custom Splunk alerts — 5 validated against live attack traffic, 2 authored for coverage of techniques present in the environment but not exercised in this run |
| **Team** | The Spelunker-People — Fullstack Academy Cybersecurity Bootcamp, April 2026 |

> **A note on addresses:** host IPs are shown as `ATTACKER_IP` / `VICTIM_IP` placeholders throughout this repo. The lab ran on an isolated VirtualBox network that reassigned RFC 1918 addresses on every 12-hour environment reset, so no single literal IP is meaningful across sessions — and redacting them is standard practice for any published security writeup.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [My Contribution](#2-my-contribution)
3. [Lab Architecture](#3-lab-architecture)
4. [Adversarial Kill Chain — Lockheed Martin Framework](#4-adversarial-kill-chain--lockheed-martin-framework)
5. [Attack Walkthroughs](#5-attack-walkthroughs)
   - [Phase 1 — Reconnaissance (netdiscover)](#phase-1--reconnaissance-netdiscover)
   - [Phase 3 — Delivery (nmap)](#phase-3--delivery-nmap)
   - [Phase 4 — Exploitation (Hydra RDP Brute Force)](#phase-4--exploitation-hydra-rdp-brute-force)
   - [Phase 5 — Installation (xfreerdp)](#phase-5--installation-xfreerdp)
6. [Splunk Detection Logic](#6-splunk-detection-logic)
7. [Dashboard & Visualizations](#7-dashboard--visualizations)
8. [Incident Response Playbook](#8-incident-response-playbook)
9. [Indicators of Compromise (IOCs)](#9-indicators-of-compromise-iocs)
10. [False Positive Analysis](#10-false-positive-analysis)
11. [Defensive Recommendations](#11-defensive-recommendations)
12. [Lessons Learned](#12-lessons-learned)
13. [Environment Notes & Known Limitations](#13-environment-notes--known-limitations)
14. [Team & Roles](#14-team--roles)
15. [References & Framework Mappings](#15-references--framework-mappings)

---

## 1. Executive Summary

This project simulates a complete adversarial intrusion lifecycle against an isolated Windows Server 2022 target, monitored in real time by Splunk Enterprise 9.4.3. Beginning with passive host discovery and progressing through port scanning, RDP credential brute-force, and authenticated post-exploitation access, the simulation is mapped end-to-end against the Lockheed Martin Cyber Kill Chain — reconnaissance through actions on objectives, with containment applied before lateral movement.

Seven custom Splunk detection rules were authored, tuned, and documented; five were validated against live attack telemetry generated during the simulation, and two were authored for coverage of adjacent techniques (password spraying, data exfiltration) not exercised by this specific attack path. A Tier 1 and Tier 2 Incident Response playbook was produced in professional SOC analyst format, alongside a structured Indicators of Compromise report and a formal defensive recommendations memo.

The lab demonstrates core SOC L1 competencies: log ingestion pipeline configuration, Windows Security Event analysis, behavioral detection rule authorship, SIEM dashboard construction, and structured incident response documentation.

---

## 2. My Contribution

**Brent Handley — Blue Team Analyst: Detection Engineering, Dashboard Design, and Incident Documentation**

My work on this project covered the full analyst-facing layer of the SOC stack: translating raw attack telemetry into tuned detections, building the monitoring interface an analyst would actually work from, and producing the formal incident documentation that closes the loop on a response.

**Splunk Detection Engineering.** I authored and tuned all seven custom Splunk alerts, owning both the SPL logic and the operational decisions behind each one — threshold selection, grouping windows, field selection, and false positive analysis. The detection I'm most satisfied with is Alert 3 (Brute Force Success). The naive approach catches *failures*, but the real signal is a source IP that failed repeatedly and then succeeded — that correlation across event types, in the same window, from the same source, is what separates an actionable alert from background noise. I refactored this alert from a `join`-based correlation to a single-pass `stats count(eval(...))` pattern, eliminating Splunk's subsearch row limit and improving scalability across multi-tenant indexes — the kind of environment an MSP SOC actually runs in. Every alert ships with a documented false positive scenario and a tuning recommendation, because an alert nobody trusts gets ignored, and the goal was a detection set worth paying attention to.

**Dashboard Build.** I designed and built the `SOC Lab — Threat Monitoring` classic dashboard in Splunk Enterprise. The six-panel layout is sequenced to match how an L1 analyst actually works a triage: *did something happen* (failed vs. successful logins) → *when did it spike* (event timeline) → *what's the current alert load* (live count) → *who is it* (top attacking IPs) → *how urgent* (severity breakdown) → *what's the full sequence* (kill chain timeline table). The panel order isn't decorative — it's the triage path.

**Incident Documentation.** I authored both formal deliverables that close the SOC response loop: the [IR Playbook](./IR-PLAYBOOK.md) (PB-2026-001), written in dual-tier format so Tier 1 triage and containment hand off cleanly to Tier 2 forensics and remediation; and the [IOC Report](./IOC-REPORT.md) (IR-20260413-001), a structured catalog of every observable artifact with confidence ratings, formatted for direct ingestion into a threat intel platform. The test I applied to both: could a Tier 1 analyst who wasn't in the room follow this and make the right call?

---

## 3. Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Isolated VirtualBox Network                  │
│                                                                  │
│   ┌─────────────────────┐          ┌─────────────────────────┐  │
│   │   KALI LINUX          │          │   WINDOWS SERVER 2022   │  │
│   │   ATTACKER_IP          │          │   VICTIM_IP             │  │
│   │                      │          │                         │  │
│   │  ┌────────────────┐  │ ATTACKS  │  ┌───────────────────┐  │  │
│   │  │ Splunk Ent.    │  │ ───────► │  │ RDP Port 3389     │  │  │
│   │  │ 9.4.3 :8000    │  │          │  └───────────────────┘  │  │
│   │  └────────────────┘  │          │                         │  │
│   │                      │          │  ┌───────────────────┐  │  │
│   │  ┌────────────────┐  │◄─────────│  │ Universal Fwd     │  │  │
│   │  │ Port 9997      │  │  LOGS    │  │ 9.4.0 :9997       │  │  │
│   │  │ (receiver)     │  │          │  └───────────────────┘  │  │
│   │  │                │  │          │                         │  │
│   │  │ Attack Tools:  │  │          │  ┌───────────────────┐  │  │
│   │  │ netdiscover    │  │          │  │ Windows Firewall  │  │  │
│   │  │ nmap           │  │          │  │ EventLog Security │  │  │
│   │  │ Hydra          │  │          │  │ 4624/4625         │  │  │
│   │  │ xfreerdp       │  │          │  │ 5156/5157/5158    │  │  │
│   │  └────────────────┘  │          │  └───────────────────┘  │  │
│   └─────────────────────┘          └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Log flow:** Windows Security Events → Universal Forwarder → port 9997 → Splunk `main` index → SPL detection rules → triggered alerts → dashboard panels

**Key configuration file:** `inputs.conf` on the Windows host controls exactly which event logs the Forwarder ships. Without a `[WinEventLog://Security]` stanza with `index = main`, the pipeline produces no data regardless of network connectivity.

![Splunk confirming Windows host connected and forwarding](https://github.com/user-attachments/assets/22db1cc9-58ce-4e7e-a1b5-23c26fb9de4c)
*Splunk showing the Windows Server host actively forwarding Security event data — confirms the log pipeline is live before any attack begins.*

---

## 4. Adversarial Kill Chain — Lockheed Martin Framework

The Lockheed Martin Cyber Kill Chain describes seven attacker-side phases. This lab maps each phase to a specific tool, observable Windows telemetry, and MITRE ATT&CK technique — with one deliberate note: Installation and Command & Control overlap in this scenario, because the RDP session itself is simultaneously the attacker's foothold and their live control channel. A real-world intrusion would more often separate these.

| Phase | LM Stage | Tool | What Happened | EventCode | MITRE Technique |
|---|---|---|---|---|---|
| **1** | Reconnaissance | `netdiscover` | ARP sweep of `VICTIM_SUBNET.0/24` — confirmed Windows host at `VICTIM_IP` | 5156 · 5157 | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) |
| **2** | Weaponization | Manual prep | 60-entry password wordlist assembled; Hydra configured to target the Administrator account over RDP | — | Supports T1110.001 |
| **3** | Delivery | `nmap -sS -T4 -p-` | SYN scan of all 65,535 ports — confirmed RDP (3389/tcp) open, identified as the delivery surface | 5156 · 5157 · 5158 | [T1046](https://attack.mitre.org/techniques/T1046/) |
| **4** | Exploitation | `Hydra` | Automated RDP brute force — `Password.1!!` found at attempt ~127 of 192 | 4625 ×58 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| **5** | Installation | `xfreerdp` | Authenticated RDP session opened as Administrator (Logon Type 10) — full GUI foothold established | 4624 | [T1078](https://attack.mitre.org/techniques/T1078/) |
| **6** | Command & Control | `xfreerdp` (live session) | The interactive RDP session functions as the C2 channel — attacker has real-time, hands-on-keyboard control | 4624 | [T1078](https://attack.mitre.org/techniques/T1078/) |
| **7** | Actions on Objectives | Windows Firewall (defender action) | **Simulation stopped and contained here** — inbound block rule applied against `ATTACKER_IP` before any lateral movement or data access occurred | 5157 (post-block) | [T1562.004](https://attack.mitre.org/techniques/T1562/004/) |

> Detection (Splunk real-time alerting on the port scan, brute force threshold, and brute force success) ran continuously in parallel with Phases 3–6, not as a separate kill chain stage — full attack visibility is documented in [Section 6](#6-splunk-detection-logic) and the [Dashboard](#7-dashboard--visualizations).

---

## 5. Attack Walkthroughs

### Phase 1 — Reconnaissance (netdiscover)

**Objective:** Identify live hosts on the network without triggering active connection logs.

```bash
sudo netdiscover -r VICTIM_SUBNET.0/24 -P
```

**What it does:** Sends ARP requests across the subnet. ARP operates at Layer 2 — it doesn't generate Windows authentication events. The result is a table of live IPs and their MAC addresses with vendor identification.

**Lab result:**
```
IP            At MAC Address     Count   Len  MAC Vendor / Hostname
VICTIM_IP     08:00:27:ba:97:95    1      60  PCS Systemtechnik GmbH (VirtualBox NIC)
```

![netdiscover confirming live host on the target subnet](https://github.com/user-attachments/assets/adc19236-9fda-4c32-9bb9-0944452a0a35)
*netdiscover's ARP sweep identifying the Windows target — this phase generates no Windows Security log entries, which is the point.*

**Why it matters defensively:** ARP-based recon often goes undetected without dedicated network monitoring. In this lab, Windows Filtering Platform auditing enabled visibility into the subsequent scan activity (EventCode 5157), but the ARP sweep itself generates no Windows Security log entries. In production, network-layer visibility (via NetFlow, NDR, or IDS) would be required to catch this phase.

**Splunk visibility:** Indirect — the ARP sweep itself does not appear in Windows Security logs. The subsequent nmap scan does.

---

### Phase 3 — Delivery (nmap)

**Objective:** Map open ports and identify attack surface on the confirmed target.

```bash
sudo nmap -sS -T4 -p- VICTIM_IP
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

![nmap confirming RDP port 3389 open on the target](https://github.com/user-attachments/assets/6ace0c68-3534-499a-a63f-b2439e6b29c9)
*nmap's SYN scan confirming port 3389 (RDP) open — this is the delivery surface the rest of the attack chain uses.*

**Windows Filtering Platform events generated:**
- `EventCode 5156` — allowed connection (open ports responding with SYN-ACK)
- `EventCode 5157` — blocked connection (closed ports returning RST)
- `EventCode 5158` — port bind events

> **Note:** These events only appear because Windows Filtering Platform auditing was enabled with:
> `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable`
> Without this one command, nmap scans are completely invisible to Splunk.

![auditpol confirming Filtering Platform auditing enabled](https://github.com/user-attachments/assets/793c3b75-27bc-49a9-80f3-fa051bcb8f7e)
*Confirmation that Filtering Platform Connection auditing is active — the prerequisite that makes the port scan visible in Splunk at all.*

**SPL to confirm in Splunk:**
```splunk
index=main sourcetype="WinEventLog:Security" (EventCode=5156 OR EventCode=5157 OR EventCode=5158)
| stats count by EventCode, src_ip
| sort - count
```

---

### Phase 4 — Exploitation (Hydra RDP Brute Force)

**Objective:** Obtain valid credentials for the Administrator account via automated password guessing.

```bash
hydra -l Administrator -P ~/passwords.txt -t 4 -V rdp://VICTIM_IP
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
- `Source Network Address: ATTACKER_IP` ← attacker IP

**Lab result:** Password `Password.1!!` found at approximately attempt 127 of 192. Before success, 58 EventCode 4625 entries were generated in the Splunk index from source IP `ATTACKER_IP`.

![Hydra brute force running against the RDP target](https://github.com/user-attachments/assets/21db3748-1942-43c6-b3a3-a4306b83c5e9)
*Hydra iterating the wordlist against the Administrator account over RDP.*

![Splunk dashboard showing the attack spike in real time](https://github.com/user-attachments/assets/748acc90-4d31-4e40-a623-1b172714260a)
*The same attack, seen from the SIEM — a sharp spike in failed logon activity coinciding with the Hydra run.*

![EventCode 4625 velocity from a single source IP](https://github.com/user-attachments/assets/5d6cc96c-29eb-4611-867c-d0ee9fb408fd)
*Attempt velocity from ATTACKER_IP — this rate and volume from one source is the exact behavioral pattern Alert 1 targets.*

![Splunk showing the full 4625 failure spike](https://github.com/user-attachments/assets/554ea183-48dd-42a5-b3af-f0469c2cc1ac)
*58 failed logon events logged before the password was found — the complete failure sequence.*

![Raw EventCode 4625 event detail, expanded](https://github.com/user-attachments/assets/28f4a859-fa82-465b-8196-0b695236ea1a)
*Raw event fields — Logon Type, Authentication Package, and Source Network Address, the fields every downstream detection depends on.*

**Why the timing matters:** Hydra with `-t 4` generates multiple attempts per second. The 58 failures in rapid succession from a single IP is the exact behavioral pattern the brute force detection alert targets — not the content of any individual failure, but the velocity and volume from one source.

---

### Phase 5 — Installation (xfreerdp)

**Objective:** Use the compromised credentials to establish a live authenticated session on the target host.

```bash
xfreerdp /u:Administrator /p:'Password.1!!' /v:VICTIM_IP
```

**What it does:** Opens a full Remote Desktop session as Administrator. A complete Windows desktop renders on the Kali screen. The attacker now has GUI-level access identical to a local admin sitting at the physical machine.

**What Windows logs:** A single `EventCode 4624` (Successful Logon) with:
- `Logon Type: 10` (RemoteInteractive — specifically RDP)
- `Authentication Package: NTLM`
- `Source Network Address: ATTACKER_IP` ← Kali IP
- `Account Name: Administrator`

![Successful xfreerdp login as Administrator](https://github.com/user-attachments/assets/c0d20953-70ba-480d-8819-2ece89ae76f6)
*Authenticated RDP session established — full GUI access as Administrator, confirming the credential from Phase 4 was valid.*

**Why this is the hardest event to detect in isolation:** A single 4624 from a valid Administrator account is indistinguishable from a legitimate admin login. The detection logic that matters here is *context* — the same IP that generated 58× EventCode 4625 just generated a 4624. Without correlating those two event types across the same source IP and time window, the successful login looks completely normal.

**This is the exact scenario Alert 3 catches** — and the centerpiece of the IR playbook.

---

## 6. Splunk Detection Logic

> All SPL queries were tested against live attack telemetry unless noted. Comments explain each clause.

### Alert 1 — Failed Login Threshold (Baseline Brute Force)

**Severity:** High | **Trigger:** 5+ EventCode 4625 from one IP within 5 seconds | **Status:** Validated live

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

**Severity:** High | **Trigger:** One IP contacts 20+ unique destination ports within 60 seconds | **Status:** Validated live

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

**Severity:** High | **Trigger:** IP with 3+ failures has at least one success | **Status:** Validated live — refactored for production scale

```splunk
/* Refactored from join-based to stats-based correlation — eliminates the
   subsearch row limit (50k default) and subsearch timeout (60s) that a
   `join` imposes. Single-pass search scales to production event volumes
   across multi-tenant indexes — the environment an MSP SOC actually runs. */

index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as fail_count,     /* failures per src_ip */
        count(eval(EventCode=4624)) as success_count   /* successes per src_ip, same pass */
    by src_ip
| where fail_count >= 3 AND success_count >= 1          /* both conditions, one search */
| eval risk=case(
    fail_count >= 10, "Critical",
    fail_count >= 3,  "High"
  )
| sort - fail_count
| table src_ip, fail_count, success_count, risk
```

**Why this alert is the most valuable:** Any IP that failed 3+ times and then succeeded is the exact behavioral fingerprint of a brute force that worked. This is what a SOC L1 escalates immediately — not the individual failures, but the success that follows them.

**Why the refactor matters:** The original version used `join type=inner`, which works at lab scale but doesn't hold up in production — Splunk's `join` command caps subsearch results and times out on large result sets. Splitting the correlation into conditional `count(eval(...))` aggregates does it in a single pass over one event stream, with no subsearch at all. It also opened the door to the `risk` field, which auto-labels severity for a triage queue instead of leaving that judgment to whoever reads the raw table.

---

### Alert 4 — New Admin Account Created

**Severity:** High | **Trigger:** EventCode 4720 (account created) or 4728 (added to privileged group) | **Status:** Authored for coverage — not exercised in this simulation (no account creation occurred in the attack path)

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

**Severity:** Medium | **Trigger:** Successful login before 08:00 or after 20:00 | **Status:** Validated live

```splunk
index=main EventCode=4624                            /* successful logins */
| eval hour=tonumber(strftime(_time, "%H"))          /* extract hour of day (UTC) */
| where hour < 8 OR hour > 20                        /* outside business hours */
| table _time, user, src_ip, host, hour              /* analyst output */
```

---

### Alert 6 — Password Spraying

**Severity:** Low | **Trigger:** One IP targets 5+ unique usernames with failures | **Status:** Authored for coverage — not exercised (the lab's attack path targeted a single account)

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

**Severity:** Medium | **Trigger:** Single host transmits >50MB outbound in one session | **Status:** Authored for coverage — not exercised (simulation was contained before any exfil attempt)

```splunk
index=main
| stats sum(bytes_out) as total_bytes_out by src_ip, host  /* sum outbound bytes per host */
| where total_bytes_out > 50000000                         /* 50MB threshold */
| eval MB_sent=round(total_bytes_out/1048576, 2)           /* convert to readable MB */
| table src_ip, host, MB_sent
| sort - MB_sent
```

---

## 7. Dashboard & Visualizations

**Dashboard name:** `SOC Lab — Threat Monitoring`
**Type:** Classic Dashboard — Splunk Enterprise 9.4.3
**Time range:** Last 60 minutes (all panels)

**Panel layout (top to bottom) — sequenced to match L1 triage order:**

| Row | Panels | Visualization | Triage Question It Answers |
|---|---|---|---|
| Row 1 | Failed vs successful logins | Bar Chart | Did something happen? |
| Row 2 | Events over time | Line Chart | When did it spike? |
| Row 3 | Live alert count | Single Value | What's the current alert load? |
| Row 4 | Top attacking IPs | Statistics Table | Who is it? |
| Row 5 | Alert severity breakdown | Pie / Donut Chart | How urgent is this? |
| Row 6 | Attack chain timeline | Statistics Table | What's the full sequence? |

![Full dashboard with all six panels populated](https://github.com/user-attachments/assets/efa9133f-3a06-428c-aa63-f2258440ddff)
*The complete SOC Lab — Threat Monitoring dashboard during the attack window — every panel answers a specific triage question, in the order an analyst would ask them.*

---

### Panel 1 — Failed vs Successful Logins Bar Chart

```splunk
index=main (EventCode=4624 OR EventCode=4625)
| eval status=if(EventCode=4624,"Success","Failure")
| stats count by status
| sort - count
```

`Visualization: Bar Chart` — X axis: status · Y axis: count

---

### Panel 2 — Events Over Time Line Chart

```splunk
index=main (EventCode=4624 OR EventCode=4625)
| eval status=if(EventCode=4624,"Success","Failure")
| timechart span=1m count by status
```

`Visualization: Line Chart` — the spike at the attack window is visually unmistakable

---

### Panel 3 — Live Alert Count Single Value

```splunk
index=_audit action=alert_fired earliest=-24h
| stats count as Total_Alerts
```

`Visualization: Single Value` — label: "Alerts Fired Today"

---

### Panel 4 — Top Attacking IPs Table

```splunk
index=main (EventCode=4624 OR EventCode=4625)
| stats count as Events,
        min(_time) as First_Seen,
        max(_time) as Last_Seen by src_ip
| eval First_Seen=strftime(First_Seen,"%H:%M:%S")
| eval Last_Seen=strftime(Last_Seen,"%H:%M:%S")
| sort - Events
| head 10
```

`Visualization: Statistics Table` — attacker IP appears at the top with highest event count

---

### Panel 5 — Alert Severity Breakdown

```splunk
index=main (EventCode=4624 OR EventCode=4625
 OR EventCode=5156 OR EventCode=5157)
| eval severity=case(
    EventCode=4625, "High",
    EventCode=4624, "High",
    EventCode=5157, "Medium",
    EventCode=5156, "Low"
  )
| stats count by severity
```

`Visualization: Pie Chart` — shows detection has depth, not everything treated as a fire alarm

---

### Panel 6 — Attack Chain Timeline

```splunk
index=main (EventCode=4624 OR EventCode=4625
 OR EventCode=5156 OR EventCode=5157)
| eval event_label=case(
    EventCode=5157, "Port Scan Blocked",
    EventCode=5156, "Port Scan Allowed",
    EventCode=4625, "Failed Login",
    EventCode=4624, "Successful Login — RDP"
  )
| table _time, event_label, src_ip, dest_port
| sort _time
```

`Visualization: Statistics Table` — complete kill chain sequence in time order

> To filter to attacker traffic only, add `| where src_ip="ATTACKER_IP"` before `| table`

---

## 8. Incident Response Playbook

See [`IR-PLAYBOOK.md`](./IR-PLAYBOOK.md) for the complete dual-tier playbook.

The playbook is authored in two formats:
- **Tier 1 SOC Analyst** — initial alert triage, validation, and containment actions within the first 15 minutes
- **Tier 2 SOC Analyst** — deep forensic investigation, root cause analysis, threat hunt, and full remediation

![Windows Firewall block rule confirmed against attacker IP](https://github.com/user-attachments/assets/cfd980ea-763b-4a8e-8a16-c6790240df15)
*The containment action from the Tier 1 playbook — inbound block rule applied at the Windows Firewall against the attacker's source IP.*

![Splunk confirming the block is holding — continued 5157 events post-containment](https://github.com/user-attachments/assets/4af094a2-9296-43d2-a812-663c2d5585cf)
*Verification query from the playbook — EventCode 5157 (blocked) entries from the attacker IP confirm the containment action is effective.*

---

## 9. Indicators of Compromise (IOCs)

See [`IOC-REPORT.md`](./IOC-REPORT.md) for the full formatted IOC table.

**Summary table:**

| IOC Type | Value | Context |
|---|---|---|
| Source IP | `ATTACKER_IP` | Kali Linux attacker — origin of all attack traffic |
| Target IP | `VICTIM_IP` | Windows Server 2022 victim host |
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

## 10. False Positive Analysis

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

## 11. Defensive Recommendations

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

## 12. Lessons Learned

*Written with professional candor — what broke, what we didn't understand, and what we'd do differently in a production environment.*

**1. The inputs.conf failure is invisible if you don't know where to look.**
The Universal Forwarder can be running as a service, showing green in the Services panel, and still shipping zero data — because without `inputs.conf`, it has no instruction on what to monitor. The diagnostic that finally revealed this was checking `splunkd.log` for `WinEventLog` entries: if there's no stanza acknowledgment, the file either doesn't exist or has a syntax error. In production, we'd configure the Splunk Deployment Server to push and enforce inputs.conf centrally rather than relying on manual file creation.

**2. Port 9997 disappears on Kali restart.**
The `splunk enable listen 9997` command doesn't survive a Kali reboot by default. Every time Kali was restarted during this project, the receiving port was gone and the forwarder had nowhere to send data. The fix is `splunk enable boot-start` combined with the listen command — in production, a systemd service unit would guarantee the port is re-enabled on every boot.

**3. The off-hours alert was UTC, not local time.**
When we first built Alert 5, it fired on logins at completely unexpected times. Splunk's `strftime` operates in UTC by default. Our lab VMs were in Eastern Time (UTC-4). The alert was triggering "off-hours" logins at what was actually 10am local time. The fix was adjusting the hour thresholds by the timezone offset. In production, always configure Splunk's server timezone and align all timestamps before building time-based detections.

**4. Alert 3 (brute force success) requires data to exist before it can be tested.**
The correlation query for "success after failures" returns nothing if you haven't run an attack first. We wasted time debugging query syntax when the real issue was that there was no matching data in the index yet. Build alerts in sequence: run the attack, verify raw events exist in Splunk, then build the alert on top of confirmed data.

**5. Logon Type 10 is the RDP fingerprint, not just EventCode 4624.**
Early in the project, Alert 3 was catching all successful logins — including local console logins, service logons, and scheduled tasks — because it searched broadly on EventCode 4624. Adding `Logon_Type=10` narrowed it specifically to Remote Interactive (RDP) sessions. This is the kind of precision that separates a noisy alert from an actionable one.

---

## 13. Environment Notes & Known Limitations

*Documented deliberately — a clear-eyed account of what the lab environment allowed and what it didn't is itself part of the analytical work.*

**Lab reset cadence.** The lab ran on a Fullstack Academy VirtualBox environment that reset automatically every 12 hours and reassigned host IPs on each cycle. All hardening (NLA, account lockout, Defender, RDP, forwarder auto-start, clock sync) was therefore scripted into a single idempotent setup routine (`lab-setup.ps1`) run once per boot, rather than applied by hand — the same discipline a real environment would demand for repeatable, auditable configuration.

**Evidence provenance.** A small number of screenshots in this repo were captured during earlier runs of the same attack sequence within the project window, and their timestamps reflect the session in which they were taken rather than one continuous capture. The underlying attack chain — recon, brute force, RDP access, SIEM detection, firewall containment — was executed and verified end to end; where a capture reflects a prior successful run, that is noted at the point of use. The full record of environment behavior and every failure mode encountered and resolved is documented in [`CONNECTION-ISSUES.md`](./splunk/lab-config/connection%20issues.md).

**Why this section exists.** Real detection engineering happens in imperfect environments. Documenting the constraints, the workarounds, and the provenance of evidence — rather than presenting a frictionless narrative — is how a working analyst reports. This section is the honest version of a lab writeup, and it is here on purpose.

---

## 14. Team & Roles

| Name | Role | Contribution |
|---|---|---|
| **Jeremy Lemmel** | Project Lead & Detection Engineer | Project architecture, Splunk alert authorship, overall coordination |
| **Luc Van Houten** | Infrastructure Engineer | VirtualBox lab setup, Universal Forwarder configuration, network topology |
| **Fadi Nasrallah** | Red Team Operator | Attack simulation design and execution — netdiscover, nmap, Hydra |
| **Brent Handley** | Blue Team Analyst | Splunk dashboard build, detection engineering and tuning, IR playbook and IOC report authorship |
| **Austin Perey** | Incident Response Analyst | IR playbook authorship, incident report, firewall containment |
| **Alison Liang** | Technical Writer & Presenter | Documentation, presentation design, video production |

**Individual contributor repositories:**

- [Jeremy Lemmel](https://github.com/JeremyLemmel/Cybersecurity-Capstone-Bruteforce-Detection)
- [Fadi Nasrallah](https://github.com/FadiNasrallah1/Threat-Detection-using-Splunk)
- [Alison Liang](https://github.com/alisonliang17/splunk-siem-lab)
- [Austin Perey](https://github.com/austinjoep/splunk-siem-lab)
- [Luc Van Houten](https://github.com/Lucvhc/splunk-siem-lab)

---

## 15. References & Framework Mappings

| Resource | Link |
|---|---|
| MITRE ATT&CK Framework | https://attack.mitre.org |
| T1595.001 — Active Scanning | https://attack.mitre.org/techniques/T1595/001/ |
| T1046 — Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |
| T1110.001 — Brute Force: Password Guessing | https://attack.mitre.org/techniques/T1110/001/ |
| T1078 — Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| T1136.001 — Create Account: Local Account | https://attack.mitre.org/techniques/T1136/001/ |
| T1562.004 — Impair Defenses: Disable or Modify System Firewall | https://attack.mitre.org/techniques/T1562/004/ |
| Lockheed Martin Cyber Kill Chain | https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html |
| Splunk Enterprise Documentation | https://docs.splunk.com/Documentation/Splunk |
| Windows Security Event Log Reference | https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview |
| Fullstack Academy Cybersecurity Bootcamp | https://www.fullstackacademy.com/programs/cybersecurity-bootcamp |

---

*Fullstack Academy Cybersecurity Bootcamp — The Spelunker-People — April 2026*
*This project was completed in an isolated lab environment. All attack simulations were conducted against systems owned and controlled by the team.*
