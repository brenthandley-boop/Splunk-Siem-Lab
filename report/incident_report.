# Cybersecurity Incident Report

**Incident Report – Tier 1 SIEM Analyst**
**Report ID:** IR-20260410-001
**Date/Time of Report:** April 10, 2026 – 12:55 PM
**Analyst Name:** [Analyst Name] – Tier 1 SIEM Analyst
**Severity:** High (Brute Force Attack in Progress)

---

## 1. Executive Summary

A brute-force attack was detected against the Windows Server 2022 (IP: `10.0.2.**`) from the Kali Linux attacker machine (IP: `10.0.2.**`). The attack chain included reconnaissance, port scanning, and password guessing via RDP. Splunk SIEM alerted on a significant spike in failed logon events (EventCode 4625). Containment action was taken by blocking the attacker IP in Windows Defender Firewall.

---

## 2. Incident Details

| Field | Details |
|-------|---------|
| Date | April 10, 2026 |
| Time | 12:38 PM |
| Location | Lab Environment (VirtualBox) |
| Type of Incident | ☑ Unauthorized Access &nbsp;&nbsp; ☑ Compromised Account Credentials |
| Detection Method | ☑ Firewall Alert or SIEM System |

**Description:**
A simulated RDP brute-force attack was launched from the attacker machine against a Windows Server target. The attack was detected in real time via Splunk SIEM monitoring Windows Security Event logs. The attacker performed host discovery, port scanning, and repeated failed login attempts before successfully authenticating via Remote Desktop Protocol (RDP).

---

## 3. Detection Details

- **SIEM Tool:** Splunk Enterprise 9.4.3
- **Alert Triggered:** Custom "Brute Force SSH/RDP Detected" alert
- **Detection Time:** April 10, 2026 – 12:38 PM
- **Key Indicators:**
  - Sudden spike in EventCode 4625 (Failed Logon) from attacker source IP `10.0.2.**`
  - High volume of failed RDP attempts (Logon Type 10)
  - Preceding Nmap scan activity (EventCodes 5156/5157/5158)

---

## 4. Timeline of Events

| Time | Event |
|------|-------|
| 12:30 PM | Reconnaissance detected — netdiscover activity (multiple ARP requests) |
| 12:32 PM | Port scanning detected — Nmap scan on ports 3389, 445, etc. |
| 12:38 PM | Brute-force attack began — Hydra RDP attempts |
| 12:46 PM | Successful login observed (EventCode 4624, Logon Type 10) |
| 12:50 PM | Analyst investigated and confirmed attack |
| 12:52 PM | Attacker IP blocked via Windows Defender Firewall rule |

---

## 5. Investigation Summary

- **Attacker tools used:**
  - `netdiscover` – Host discovery
  - `nmap` – Port scanning
  - `hydra` – RDP brute-force attack
- **Target account:** Administrator (privileged account)
- **Attack vector:** Weak password successfully guessed via automated brute force
- **Attack origin:** Kali Linux VM (`10.0.2.**`)

---

## 6. Affected Systems

| System | IP Address | Role |
|--------|-----------|------|
| Attacker Machine (Kali Linux) | `10.0.2.**` | Attack source |
| Target (Windows Server 2022) | `10.0.2.**` | Compromised host |

---

## 7. Indicators of Compromise (IOCs)

| IOC Type | Value |
|----------|-------|
| Attacker Source IP | `10.0.2.**` |
| Target IP | `10.0.2.**` |
| Target Port | 3389 (RDP) |
| EventCode (Failed Logon) | 4625 |
| EventCode (Successful Logon) | 4624 |
| EventCode (Privileged Access) | 4672 |
| Logon Type | 10 (Remote Interactive) |

---

## 8. Containment Action Taken

**Action:** Blocked the attacker IP address in Windows Defender Firewall with Advanced Security.

**Firewall Rule Created:**

| Field | Value |
|-------|-------|
| Rule Name | `Block Attacker - Kali Linux (10.0.2.**)` |
| Action | Block the connection |
| Scope (Remote IP) | `10.0.2.**` |
| Applied To | All Profiles (Domain, Private, Public) |
| Rule Type | Inbound |

The rule was created under **Inbound Rules** and is now active.

---

## 9. Recommendations

1. Change the Administrator password to a strong, complex value immediately.
2. Enable Account Lockout Policy (e.g., lock after 5 failed attempts).
3. Implement Multi-Factor Authentication (MFA) for RDP access.
4. Review and tighten Windows Firewall rules for RDP (port 3389) exposure.
5. Schedule regular password audits and enable enhanced logging.

---

## 10. Lessons Learned

- Real-time SIEM monitoring (Splunk) was effective in detecting the attack within minutes of initiation.
- EventCode 4625 spike is a reliable early indicator of brute-force activity.
- Blocking at the firewall level is a fast and effective containment method.
- Weak passwords on privileged accounts remain a critical risk — lockout policies must be enforced.

---

## Status & Next Steps

| Field | Value |
|-------|-------|
| **Status** | Contained |
| **Next Steps** | Escalate to Tier 2 for full forensic analysis and eradication if needed |

---

**Analyst Signature:** [Analyst Name] – Tier 1 SIEM Analyst
**Date:** April 10, 2026

---

> ⚠️ *This report was generated as part of a controlled cybersecurity lab exercise. No real systems were targeted. All IP addresses have been partially redacted for privacy.*
