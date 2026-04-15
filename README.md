# Splunk-Siem-Lab
Splunk SIEM Security Lab
# 🔐 Splunk SIEM Security Lab

## 📌 Project Overview
Designed and implemented a hands-on cybersecurity lab to simulate real-world attack scenarios and detect malicious activities using Splunk SIEM in real time.

The lab includes multiple stages of the attack lifecycle, including brute force attempts, unauthorized remote access, and post-exploitation activities. It demonstrates both Red Team (offensive security) and Blue Team (defensive monitoring) techniques, showcasing the ability to build, attack, detect, and defend within a controlled environment.

## 🛠️ Tools & Technologies
- Splunk Enterprise 9.4.3
- Splunk Universal Forwarder 9.4.0
- Kali Linux
- Windows Server 2022
- Netdiscover
- Namap
- Hydra
- xfreerdp
- Windows Firewall

 ## 🛠️ Architecuture

```
┌─────────────────────────────────────────────────────────────┐
│                        Lab Environment                       │
│                                                             │
│   ┌──────────────────┐        ┌──────────────────────────┐  │
│   │  Kali Linux       │──────▶│  Windows Server (victim) │  │
│   │  (Attacker)       │  RDP  │                          │  │
│   │                   │       │  ┌──────────────────┐    │  │
│   │  • NetDiscover    │       │  │ Universal         │    │  │
│   │  • Nmap           │       │  │ Forwarder         │    │  │
│   │  • Hydra          │       │  │ (port 9997)       │    │  │
│   │  • xfreerdp       │       │  └────────┬─────────┘    │  │
│   └──────────────────┘        └───────────┼──────────────┘  │
│                                           │ logs             │
│                                           ▼                  │
│                               ┌──────────────────────────┐  │
│                               │  Splunk Enterprise        │  │
│                               │  (SIEM — Kali, 10.0.2.5) │  │
│                               │                          │  │
│                               │  • index=main            │  │
│                               │  • SPL queries           │  │
│                               │  • Dashboard             │  │
│                               └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## ⚔️ Attacks Simulated

### 1. Reconnaissance — NetDiscover & Nmap

Performed network reconnaissance to discover live hosts and identify open ports on the target machine.

```bash
# Discover live hosts on the subnet
netdiscover -r 10.0.2.0/24

# Scan target for open ports and services
nmap -sV -p 3389 <TARGET_IP>
```

**Goal:** Confirm target IP and verify RDP port 3389 is open before launching the attack.

---

### 2. RDP Brute Force — Hydra

Simulated a brute force attack against the Windows Server RDP service using a custom password list.

```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://<TARGET_IP>
```

**Detection:** `EventCode 4625` — Failed Logon

---

### 3. Remote Desktop Takeover — xfreerdp

Gained full remote desktop access after successfully cracking the password.

```bash
xfreerdp /u:Administrator /p:<CRACKED_PASSWORD> /v:<TARGET_IP>
```

**Detection:** `EventCode 4624` — Successful Logon

---


## 🔵 Blue Team Defense

- **Block attacking IP** via Windows Firewall inbound rule
- **Enable account lockout** after 5 failed login attempts
- **Real-time monitoring** with Splunk dashboards
- **Automated alerts** triggered on threshold breach

```powershell
# Block attacker IP via PowerShell
New-NetFirewallRule -DisplayName "Block Attacker" `
  -Direction Inbound `
  -RemoteAddress <ATTACKER_IP> `
  -Action Block
```

---

## 📁 Repository Structure

```
splunk-siem-lab/
├── docs/
│   ├── architecture.png
│   └── dashboard.png
├── recon/
│   └── netdiscover_nmap.md
├── attack/
│   ├── hydra_commands.md
│   └── xfreerdp_commands.md
├── detection/
│   └── splunk_queries.md
├── defense/
│   └── firewall_rules.md
├── LICENSE
└── README.md
```

---

## 🎯 Key Learnings

- Built a full SIEM environment from scratch including log forwarding pipeline
- Simulated real-world attack techniques across the full kill chain
- Created real-time Splunk dashboards and automated threshold alerts
- Practiced both Red Team offensive techniques and Blue Team detection/response
- Developed hands-on experience with EventID correlation (4625 → 4624 pattern)

---

## ⚠️ Disclaimer

> All attacks were performed in an **isolated virtual machine environment** for **educational purposes only**. No real systems were targeted. This project is intended to demonstrate SOC analyst skills in a controlled lab setting.
