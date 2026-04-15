# Splunk Detection Queries

Queries used during the lab to detect a simulated RDP brute-force attack originating from the attacker machine targeting the Windows Server.

---
<img width="857" height="470" alt="image" src="https://github.com/user-attachments/assets/643a4b75-238a-4f22-8ced-7adb831da1b4" />

## 1. Detect Failed Logon Attempts (Brute Force)

Triggered by RDP brute-force tool. EventCode `4625` = failed logon.

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by src_ip, Account_Name, host
| where count > 10
| sort - count
```

**What it finds:** Source IPs with repeated failed logons — a brute-force signature.

---

## 2. Spike Detection — Failed Logons Over Time

Visualizes the brute-force spike in real time during the attack.

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| timechart span=1m count by src_ip
```

**What it finds:** A sudden spike in failed logons per minute from the attacker IP.

---

## 3. Successful Logon After Failed Attempts (Credential Compromise)

Detects a successful login (EventCode `4624`) shortly after multiple failures — indicates a cracked password.

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS failed, count(eval(EventCode=4624)) AS success by src_ip, Account_Name
| where failed > 10 AND success >= 1
| sort - failed
```

**What it finds:** Accounts where brute force was followed by a successful login.

---

## 4. Privileged Logon Detection

EventCode `4672` = special privileges assigned at logon (Administrator-level access).

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4672
| stats count by Account_Name, src_ip, host
| sort - count
```

**What it finds:** Who logged in with admin privileges — confirms Administrator access via RDP client.

---

## 5. RDP Access Confirmation

Filters for Network Logon Type 10 (remote interactive / RDP).

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| table _time, Account_Name, src_ip, host, Logon_Type
| sort - _time
```

**What it finds:** Confirms remote desktop sessions established during the attack.

---

## 6. Full Attack Timeline

Combines brute force and access events into a single timeline.

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624 OR EventCode=4672)
| eval event_type=case(
    EventCode=4625, "Failed Logon",
    EventCode=4624, "Successful Logon",
    EventCode=4672, "Privileged Access")
| table _time, event_type, Account_Name, src_ip, host
| sort _time
```

**What it finds:** End-to-end attack chain visible in one view.

---

## Attack Reference

| Phase | Tool | EventCode |
|-------|------|-----------|
| Reconnaissance | `netdiscover` | — |
| Scanning | `nmap -sS -p-` | — |
| Brute Force | `hydra` | 4625 |
| RDP Access | `xfreerdp` | 4624, 4672 |
| Detection | Splunk SIEM | all above |
| Response | Windows Defender Firewall (blocked attacker IP) | — |

---

## Environment

| Component | Value |
|-----------|-------|
| Attacker (Kali) | `10.0.2.**` |
| Target (Windows Server) | `10.0.2.**` |
| Splunk index | `main` |
| sourcetype | `WinEventLog:Security` |
