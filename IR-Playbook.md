# IR-PLAYBOOK.md — Incident Response Playbook
## Brute Force RDP Attack with Successful Credential Compromise

**Playbook ID:** PB-2026-001  
**Incident Classification:** Credential Access / Unauthorized Remote Access  
**Severity:** High  
**MITRE Techniques:** T1110.001 · T1078 · T1046  
**Authored by:** The Spelunker-People SOC Team — Fullstack Academy Cybersecurity Bootcamp  
**Review Date:** April 2026  

---

> This playbook is authored in two tiers. **Tier 1** covers the first 15 minutes — alert triage, validation, and immediate containment. **Tier 2** covers the full investigation that follows — forensic analysis, threat hunting, root cause determination, and remediation. In a real SOC, Tier 1 executes first and hands off to Tier 2 with a documented evidence package.

---

## TIER 1 — Initial Triage & Containment
*Written from the perspective of a Tier 1 SOC Analyst. Your job: determine if this alert is real, contain immediately if confirmed, and hand off with clean documentation.*

---

### T1.1 — Alert Trigger Conditions

This playbook activates when **any** of the following Splunk alerts fire:

| Alert Name | Trigger Logic | Severity |
|---|---|---|
| Failed Login Threshold | 5+ EventCode 4625 from one src_ip within 5 seconds | High |
| Port Scan Detected | One src_ip contacts 20+ unique dest_ports within 60 seconds | High |
| Brute Force Success | IP with 3+ EventCode 4625 also has EventCode 4624 | High |
| New Admin Account Created | EventCode 4720 or 4728 detected | High |

---

### T1.2 — Initial Validation (First 5 Minutes)

**Step 1: Confirm the alert is real, not a false positive.**

Open Splunk Search & Reporting. Run the following query, replacing `ATTACKER_IP` with the `src_ip` from the alert:

```splunk
index=main src_ip="ATTACKER_IP"
| table _time, EventCode, user, src_ip, host, Logon_Type
| sort _time
```

**What you're looking for:**
- [ ] Do you see a sequence of EventCode 4625 entries? (failed logins — expected for brute force)
- [ ] Is the count of failures from this IP unusually high (>10 in a short window)?
- [ ] Is there an EventCode 4624 (success) appearing after the failures?
- [ ] Is the `Logon_Type` value `10`? (10 = Remote Desktop — confirms RDP attack)
- [ ] Is the `Authentication Package` showing `NTLM`? (automated tools typically use NTLM)

**If all boxes checked → this is a confirmed brute force attack. Proceed to T1.3 immediately.**

**If boxes are NOT checked → document your finding and close as false positive. Note the benign reason (e.g., "IT admin workstation, known IP, business hours activity").**

---

**Step 2: Determine the blast radius.**

```splunk
index=main (EventCode=4624 OR EventCode=4625)
| stats count as events,
        dc(EventCode) as event_types,
        min(_time) as first_seen,
        max(_time) as last_seen
    by src_ip
| sort - events
```

- [ ] Is the attacking IP hitting only one host, or multiple?
- [ ] What is the time range of activity (first_seen to last_seen)?
- [ ] Has the 4624 success event occurred? If yes — the attacker may already be inside.

---

### T1.3 — Immediate Containment (Minutes 5–10)

**If EventCode 4624 (successful login) has occurred — the attacker is potentially active on the system right now. Containment takes priority over further investigation.**

**Action 1: Block the attacking IP at the Windows Firewall.**

On the victim Windows host:
1. Open `Windows Defender Firewall with Advanced Security`
2. Click `Inbound Rules` → `New Rule`
3. Rule Type: `Custom`
4. Program: `All programs`
5. Protocol: `Any`
6. Scope → Remote IP addresses: enter the attacker IP (e.g., `ATTACKER_IP`)
7. Action: `Block the connection`
8. Profile: Check `Domain`, `Private`, and `Public`
9. Name: `BLOCK — Attacker [src_ip] — [Date]`
10. Click Finish

**Verify the block worked:**

```splunk
index=main src_ip="ATTACKER_IP" EventCode=5157
| table _time, src_ip, dest_port
| sort - _time
```

If EventCode 5157 (connection blocked) entries appear from the attacker IP after the rule was created — the firewall rule is active and working.

---

**Action 2: Document the containment action.**

Record in your incident notes:
- Time block rule was created
- Exact rule name used
- Whether the attacker had a successful login (EventCode 4624) before containment
- If yes: timestamp of that successful login

---

### T1.4 — Tier 1 Escalation Decision

**Escalate to Tier 2 if ANY of the following are true:**

- [ ] EventCode 4624 (successful login) occurred BEFORE containment
- [ ] EventCode 4720 or 4728 detected (new account created / added to admin group)
- [ ] Attack traffic originated from an external/routable IP (not internal lab network)
- [ ] Multiple hosts were targeted (blast radius > 1 system)
- [ ] You cannot determine the full scope of access from Splunk data alone

**Tier 1 handoff package (document before escalating):**

```
Incident ID:        IR-[YYYYMMDD]-[###]
Alert Triggered:    [Alert Name]
Detection Time:     [Timestamp from Splunk]
Attacker IP:        [src_ip value]
Target Host:        [host value]
Target Account:     [user value]
Successful Login?:  [Yes/No] — [Timestamp if Yes]
Containment Action: [Firewall block rule created at HH:MM]
Splunk Query Used:  [paste the SPL]
Analyst:            [Your Name] — Tier 1 SOC
```

---

### T1.5 — Tier 1 Closeout (If No Escalation Needed)

If no successful login occurred AND the block rule stopped all activity, document the incident as contained and close:

**Incident Status:** Contained  
**Resolution:** Brute force attack detected and blocked before credential compromise. No evidence of successful access. Firewall rule created. Monitoring continued for 30 minutes post-containment with no recurrence.

---
---

## TIER 2 — Deep Investigation & Remediation
*Written from the perspective of a Tier 2 SOC Analyst. You've received a handoff from Tier 1 confirming a successful RDP login occurred. Your job: determine everything the attacker did after gaining access, assess the full impact, and drive remediation to completion.*

---

### T2.1 — Establish the Full Attack Timeline

Begin by reconstructing a complete chronological record of all attacker activity. This is your evidence foundation for everything that follows.

```splunk
index=main (src_ip="ATTACKER_IP" OR host="TARGET_HOST")
| eval event_label=case(
    EventCode=5157, "Firewall Block",
    EventCode=5156, "Firewall Allow",
    EventCode=4625, "Failed Login",
    EventCode=4624, "Successful Login",
    EventCode=4720, "Account Created",
    EventCode=4728, "Added to Admin Group",
    true(), "Other: ".EventCode
  )
| table _time, event_label, src_ip, user, host, Logon_Type
| sort _time
```

Document the timeline:

| Timestamp | Event | Significance |
|---|---|---|
| [HH:MM] | ARP/discovery activity (EventCode 5156/5157 spike) | Reconnaissance phase |
| [HH:MM] | Port scan (bulk EventCode 5157 — 65,535 ports) | Attack surface mapping |
| [HH:MM] | First EventCode 4625 from attacker IP | Brute force begins |
| [HH:MM] | Last EventCode 4625 before success | Last failed attempt |
| [HH:MM] | EventCode 4624, Logon Type 10 | **Successful RDP access — attacker inside** |
| [HH:MM] | EventCode 4720 / 4728 (if present) | Persistence attempt |
| [HH:MM] | Firewall block rule created | Containment |

---

### T2.2 — Determine What the Attacker Did Post-Access

Once inside via xfreerdp, the attacker had full GUI access. Check for post-exploitation activity:

**Check for new accounts (persistence):**
```splunk
index=main host="TARGET_HOST" (EventCode=4720 OR EventCode=4728)
| table _time, EventCode, user, src_user
| sort _time
```

**Check for privilege escalation:**
```splunk
index=main host="TARGET_HOST" EventCode=4672
| table _time, user, src_ip, Privileges
```
EventCode 4672 = Special Privileges Assigned to New Logon. This fires when an account with admin-level privileges logs on.

**Check for process execution (if Sysmon is installed):**
```splunk
index=main host="TARGET_HOST" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=1
| table _time, user, CommandLine, ParentCommandLine
| sort _time
```

**Check for lateral movement to other hosts:**
```splunk
index=main src_ip="ATTACKER_IP" OR src_ip="TARGET_HOST_IP"
| stats count by host, src_ip, EventCode
| sort - count
```

---

### T2.3 — Threat Hunt — Did the Attacker Establish Persistence?

Even if no EventCode 4720/4728 was detected, check for other persistence mechanisms:

**Scheduled tasks created:**
```splunk
index=main host="TARGET_HOST" EventCode=4698
| table _time, user, TaskName, TaskContent
```
EventCode 4698 = Scheduled Task Created.

**Registry run key modifications (requires Sysmon):**
```splunk
index=main host="TARGET_HOST" EventCode=13
    (TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*")
| table _time, user, TargetObject, Details
```

**Local user accounts currently on the system:**
Verify on the Windows host: `net user` — compare against known-good baseline. Any account not in the baseline is a backdoor.

---

### T2.4 — Root Cause Analysis

**Primary failure:** Weak administrative password (`Password.1!!`) exposed via RDP to the network without rate limiting or account lockout. The password appeared in position 127 of a 192-entry common password wordlist.

**Contributing factors:**
1. No account lockout policy — allowed unlimited guessing attempts
2. RDP exposed to full network with no source IP restriction
3. No MFA on administrative account
4. NTLM authentication allowed — enabling automated brute force tools
5. No network-layer monitoring — recon phase (netdiscover) was invisible

**Detection lag:** The attack began at the reconnaissance phase. Our Splunk detection fired at the brute force phase (EventCode 4625 threshold). There was a gap of approximately 8 minutes between first attacker activity and first alert. In a production environment, reducing this detection gap is a priority — ideally catching the recon phase with network-layer visibility.

---

### T2.5 — Remediation Checklist

**Immediate (within 24 hours):**
- [ ] Change Administrator password to complex, randomly generated value (20+ characters)
- [ ] Verify new backdoor accounts do not exist (`net user` audit)
- [ ] Verify no new scheduled tasks were created
- [ ] Confirm firewall block rule is still active and attacker IP is blocked
- [ ] Review all EventCode 4624 entries from the attacker's session for commands executed

**Short-term (within 1 week):**
- [ ] Enable account lockout policy: 5 failures → 30-minute lockout
- [ ] Restrict RDP inbound rule to authorized management IPs only
- [ ] Enforce MFA on all remote access (RDP, VPN, admin portals)
- [ ] Disable NTLM authentication, enforce Kerberos where applicable
- [ ] Enable Windows Filtering Platform auditing (`auditpol`) on all hosts

**Long-term (within 30 days):**
- [ ] Deploy Sysmon for process-level visibility on all endpoints
- [ ] Configure Splunk forwarder health monitoring alert
- [ ] Conduct full password audit — identify all accounts with weak/common passwords
- [ ] Implement privileged access workstation (PAW) controls for admin activity
- [ ] Schedule quarterly red team exercise to verify detection coverage

---

### T2.6 — Formal Incident Report

*Authored in the format of a professional Managed Detection & Response advisory.*

---

```
════════════════════════════════════════════════════════════════
INCIDENT REPORT — SIMULATED MANAGED DETECTION & RESPONSE
Modeled after enterprise MDR advisory format
════════════════════════════════════════════════════════════════

Report ID:          IR-20260413-001
Severity:           HIGH — Credential Compromise / Unauthorized Remote Access
Detection Source:   Splunk Enterprise 9.4.3 — Custom Alert: Brute Force Success
Report Date:        April 13, 2026 — 12:55 PM EDT
Analyst (T1):       Tier 1 SOC Analyst — The Spelunker-People SOC Team
Analyst (T2):       Tier 2 SOC Analyst — The Spelunker-People SOC Team
Status:             CONTAINED

════════════════════════════════════════════════════════════════
1. EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════

A brute-force credential attack was detected against Windows Server 2022
(VICTIM_IP) originating from Kali Linux (ATTACKER_IP). The attack chain
included passive host discovery via ARP sweep, active port scanning
confirming RDP on 3389/tcp, automated password guessing via Hydra (58
failed EventCode 4625 entries), and a successful RDP authentication as
Administrator (EventCode 4624, Logon Type 10).

Splunk alerted on the failed login velocity threshold. Containment was
executed by the T1 analyst via Windows Defender Firewall inbound block
rule targeting the source IP. Post-containment, EventCode 5157 entries
confirm the attacker's IP is being silently dropped.

No evidence of persistence mechanisms (account creation, scheduled tasks,
registry modifications) was detected in this simulation. The attack was
fully contained within 22 minutes of initial reconnaissance activity.

════════════════════════════════════════════════════════════════
2. DETECTION DETAILS
════════════════════════════════════════════════════════════════

SIEM Platform:      Splunk Enterprise 9.4.3
Alert Triggered:    "Brute Force Success — Login After Multiple Failures"
Detection Time:     April 13, 2026 — 12:38 PM EDT
Time to Contain:    14 minutes from alert firing

Key Indicators:
  • Sudden spike in EventCode 4625 (Failed Logon) from ATTACKER_IP
  • 58 failed RDP attempts (Logon Type 10) in approximately 90 seconds
  • NTLM authentication package — consistent with automated tooling
  • Preceding nmap scan activity (EventCodes 5156/5157/5158)
  • EventCode 4624 (Logon Type 10) from same source IP at 12:46 PM

════════════════════════════════════════════════════════════════
3. TIMELINE OF EVENTS
════════════════════════════════════════════════════════════════

12:30 PM — Reconnaissance: netdiscover ARP sweep — host VICTIM_IP discovered
12:32 PM — Scanning: nmap SYN scan — port 3389/tcp confirmed open (91 seconds)
12:38 PM — Exploitation: Hydra brute force initiated — EventCode 4625 spike
12:46 PM — Access: Successful RDP login — EventCode 4624, Logon Type 10
12:50 PM — T1 Analyst: Alert investigated, attack confirmed, escalation assessed
12:52 PM — Containment: Attacker IP ATTACKER_IP blocked via Windows Firewall rule

════════════════════════════════════════════════════════════════
4. INVESTIGATION SUMMARY
════════════════════════════════════════════════════════════════

Attack tools used:
  • netdiscover — passive host discovery (ARP)
  • nmap        — active port scanning (SYN scan, all ports)
  • Hydra        — RDP credential brute force
  • xfreerdp     — post-brute-force RDP client access

Target account:     Administrator (local)
Credential found:   Password.1!! (position 127/192 in wordlist)
Attack duration:    ~22 minutes from first activity to containment
Evidence volume:    58 EventCode 4625 + 1 EventCode 4624 in Splunk index

════════════════════════════════════════════════════════════════
5. CONTAINMENT ACTION TAKEN
════════════════════════════════════════════════════════════════

Action:     Inbound block rule created in Windows Defender Firewall
            with Advanced Security targeting remote IP ATTACKER_IP.

Rule Name:  BLOCK — Attacker Kali Linux ATTACKER_IP
Scope:      Remote IP = ATTACKER_IP
Action:     Block the connection
Applied to: Domain, Private, Public profiles

Verification: Post-block EventCode 5157 entries confirm rule active.
Status:     CONTAINED — no new successful logins observed post-block.

════════════════════════════════════════════════════════════════
6. RECOMMENDATIONS
════════════════════════════════════════════════════════════════

P1 — Enforce MFA on all RDP sessions immediately
P2 — Enable account lockout policy (5 failures → 30-minute lockout)
P2 — Restrict RDP inbound to authorized management IPs only
P3 — Disable NTLM, enforce Kerberos authentication
P3 — Conduct full password audit across all administrative accounts
P4 — Deploy Sysmon for process-level post-exploitation visibility
P4 — Schedule quarterly adversarial simulation to validate detection coverage

════════════════════════════════════════════════════════════════
Analyst Signatures:
  Tier 1: [T1 Analyst Name] — Tier 1 SOC Analyst — April 13, 2026
  Tier 2: [T2 Analyst Name] — Tier 2 SOC Analyst — April 13, 2026
Next Steps: Monitor for re-attempt from new IPs. Validate recommendations
            implemented within SLA. Schedule post-incident review.
════════════════════════════════════════════════════════════════
```

---

*This playbook is maintained by The Spelunker-People SOC Team.*  
*It should be reviewed and updated after any real or simulated incident.*  
*Fullstack Academy Cybersecurity Bootcamp — April 2026*
