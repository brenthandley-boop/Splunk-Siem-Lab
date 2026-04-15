# Windows Firewall – Block Attacker IP (Incident Response)

## Description

After detecting suspicious activity in Splunk (multiple failed RDP login attempts – EventCode 4625), the attacker IP address was blocked using Windows Defender Firewall.

<img width="1779" height="393" alt="firewall1_redacted (1)" src="https://github.com/user-attachments/assets/ed130f5e-32d1-41c6-a773-1a2d77d11525" />


This demonstrates the **Response / Containment** phase of the Cyber Kill Chain.

The attacker system (Kali Linux) was prevented from continuing brute-force attempts against the Windows Server.

---

## Create Firewall Rule to Block Attacker

Open **Windows Defender Firewall with Advanced Security**

### Step 1 – Navigate to Inbound Rules

Left panel:

```
Inbound Rules
```

Right panel:

```
New Rule...
```

---
<img width="1255" height="681" alt="firewall_redacted" src="https://github.com/user-attachments/assets/9cddd08d-fb2a-46f2-9f07-838fd379e5ad" />


### Step 2 – Rule Configuration

Rule Type:

```
Custom
```

Program:

```
All programs
```

Protocol and Ports:

```
Any
```

Scope:

Under remote IP addresses:

```
These IP addresses → Add → 10.0.*.*
```

Action:

```
Block the connection
```

Profile:

```
Domain
Private
Public
```

---
<img width="1257" height="681" alt="firewall4" src="https://github.com/user-attachments/assets/6fe0fd4e-6594-4890-8f0d-10324ec9567c" />


### Step 3 – Name the Rule

Example:

```
Name:
Block Attacker - Kali Linux (10.0.2.5)

Description:
Incident Response - Block brute-force attacker from Kali after detection in Splunk
```

Click Finish.

---

## Expected Result

The Kali Linux attacker machine can no longer connect to the Windows Server via RDP.

Further brute-force attempts will fail due to firewall restrictions.

---


Indicators of attack:

* High volume failed logons
* Repeated attempts from single IP address
* Target account: Administrator
* Protocol: RDP (3389)

---

## Cyber Kill Chain Mapping

| Phase | Tool |
|------|------|
| Reconnaissance | netdiscover |
| Scanning | nmap |
| Exploitation | hydra |
| Access | xfreerdp |
| Detection | Splunk SIEM |
| Response | Windows Firewall block rule |

---

## Security Insight

Blocking malicious IP addresses is a common containment step during incident response.

Firewall rules help:

* stop brute-force attacks
* prevent lateral movement
* reduce attacker persistence
* protect exposed services

This demonstrates how SIEM detection integrates with defensive controls.
