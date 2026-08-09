# IOC-REPORT.md — Indicators of Compromise
## Incident IR-20260413-001 — RDP Brute Force with Credential Compromise

**Report ID:** IR-20260413-001  
**Incident Type:** Credential Brute Force / Unauthorized Remote Access  
**Detection Date:** April 13, 2026  
**MITRE Techniques:** T1595.001 · T1046 · T1110.001 · T1078  
**Authored by:** The Spelunker-People SOC Team — Fullstack Academy Cybersecurity Bootcamp  

---

> **Purpose:** This document catalogs every observable artifact produced by the simulated attack. In a real incident, these IOCs would be fed into a threat intelligence platform (MISP, ThreatConnect, or a SIEM threat intel feed) to enable automated detection of the same attacker across other systems.

---

## Network Indicators

| IOC Type | Value | Description | Confidence |
|---|---|---|---|
| IPv4 Address — Attacker | `10.0.2.5` | Kali Linux attacker machine — source of all attack traffic | High |
| IPv4 Address — Victim | `10.0.2.15` | Windows Server 2022 victim host — all attack traffic destined here | High |
| Destination Port | `3389/tcp` | RDP — the targeted service for brute force and access | High |
| Protocol | RDP (Remote Desktop Protocol) | Layer 7 protocol used for authentication attempts and access | High |
| Authentication Package | `NTLM` | Used during all RDP authentication attempts — visible in EventCode 4625 `AuthenticationPackageName` field | High |
| Network Pattern | SYN packets to 65,535 ports in ~91 seconds from single source | Behavioral signature of nmap `-p-` all-ports scan | High |

---

## Host Indicators — Windows Server 2022 (10.0.2.15)

| IOC Type | Value | Description | Confidence |
|---|---|---|---|
| Target Account | `Administrator` | Local administrator account — targeted exclusively by Hydra `-l Administrator` | High |
| Logon Type | `10` (RemoteInteractive) | RDP-specific logon code — distinguishes from local console or service logons | High |
| Logon Type (brute force attempts) | `3` (Network) | Some failed attempts recorded as Type 3 during Hydra scanning phase | Medium |
| Failure Reason Code | `0xC000006A` | "Unknown user name or bad password" — returned for wrong password attempts | High |
| Sub-Status Code | `0xC0000064` | "User does not exist" — returned for non-existent usernames | Medium |
| Computer Name | `WIN-5G7PV0LGRB1` | Target hostname visible in EventCode 4625 `ComputerName` field | High |

---

## Windows Event Log Indicators

| EventCode | Meaning | Attack Phase | Volume Observed |
|---|---|---|---|
| `5157` | Windows Filtering Platform blocked connection | nmap scan (closed ports) | High — hundreds in ~91 seconds |
| `5156` | Windows Filtering Platform allowed connection | nmap scan (open ports) | Low — only open ports |
| `5158` | Bind to local port | Port binding during scan | Low |
| `4625` | Failed logon — "An account failed to log on" | Hydra brute force | 58 events in ~90 seconds |
| `4624` | Successful logon — "An account was successfully logged on" | xfreerdp access | 1 event post-brute-force |
| `4672` | Special privileges assigned to new logon | Admin account logon | Fires with 4624 for admin accounts |

---

## Behavioral Indicators (TTPs)

| Behavior | Observable | MITRE Technique |
|---|---|---|
| ARP sweep of subnet | Multiple ARP requests from single MAC in short window — not visible in Windows logs, visible in network capture | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) |
| Port scan — all ports | 5157/5156 spike from single src_ip, dc(dest_port) > 20 in 60 seconds | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Credential brute force | 5+ EventCode 4625 from single src_ip within 5-second window | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Velocity pattern | ~4 attempts/second (Hydra `-t 4`) — distinguishable from human login timing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Post-brute success | EventCode 4624 Logon_Type=10 from same src_ip that generated failures | [T1078](https://attack.mitre.org/techniques/T1078/) |
| NTLM usage | `AuthenticationPackageName: NTLM` in 4625/4624 events — automated tools default to NTLM | [T1078](https://attack.mitre.org/techniques/T1078/) |

---

## Splunk Correlation Search — IOC Hunter

Use this query to hunt for these IOCs across any Splunk environment:

```splunk
index=main
  (src_ip="10.0.2.5"
   OR (EventCode=4625 AND Logon_Type=10)
   OR (EventCode=4624 AND Logon_Type=10 AND AuthenticationPackageName=NTLM)
   OR (EventCode=5157 AND src_ip="10.0.2.5"))
| eval ioc_match=case(
    src_ip="10.0.2.5", "Known Attacker IP",
    EventCode=4625 AND Logon_Type=10, "RDP Brute Force Attempt",
    EventCode=4624 AND Logon_Type=10, "RDP Successful Login",
    EventCode=5157, "Firewall Block — Port Scan"
  )
| table _time, ioc_match, src_ip, user, host, EventCode
| sort _time
```

---

## Timeline of IOC Appearance

```
12:30 PM ──── ARP sweep (netdiscover) ────────── No Windows log — network-layer only
12:32 PM ──── EventCode 5156/5157 spike ────────── nmap SYN scan begins
12:33 PM ──── EventCode 5158 ─────────────────── Port bind events
12:38 PM ──── EventCode 4625 (first) ────────────── Hydra brute force begins
12:38 PM ──── EventCode 4625 (×58) ──────────────── Rapid failure sequence (NTLM, Type 10)
12:46 PM ──── EventCode 4624 (Logon_Type=10) ─── SUCCESSFUL LOGIN — attacker inside
12:52 PM ──── EventCode 5157 (post-block) ────── Firewall rule active — attack contained
```

---

## IOC Disposition

| IOC | Action Taken | Status |
|---|---|---|
| `10.0.2.5` | Blocked via Windows Defender Firewall inbound rule | Contained |
| Administrator account | Password reset recommended | Pending |
| NTLM authentication | Disable policy recommended | Pending |
| RDP exposure | Restrict to authorized IPs recommended | Pending |

---

*This IOC report is part of Incident IR-20260413-001.*  
*Fullstack Academy Cybersecurity Bootcamp — The Spelunker-People — April 2026*
