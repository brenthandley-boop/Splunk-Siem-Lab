# Recon Phase – Network Discovery

## Overview

Reconnaissance (Recon) is the first phase of the attack lifecycle.

The goal is to gather information about the target environment, including:

* active hosts
* IP addresses
* open ports
* running services

Understanding exposed services helps identify potential entry points and reduce security risk.

---

## Tools Used

### 1. Netdiscover

Used to identify active hosts on the local network.

Command:

```bash
netdiscover -r 10.0.x.0/24 -P
```

<img width="1511" height="292" alt="image" src="https://github.com/user-attachments/assets/05faeaba-ce49-4a0c-81ab-4e8fbb685ec4" />


Purpose:

* discover live hosts
* identify IP addresses in the network
* map network structure

---

### 2. Nmap

Used to scan open ports and detect running services.

Command:

```bash
nmap -sS -T4 -p- TARGET_IP
```

Command explanation:

| Option | Description       |
| ------ | ----------------- |
| -sS    | stealth SYN scan  |
| -T4    | faster scan speed |
| -p-    | scan all ports    |

---

## Scan Result

<img width="1440" height="360" alt="image" src="https://github.com/user-attachments/assets/793f34a6-f968-4155-a28e-45f927a12374" />

---

## Key Findings

The scan identified the following open ports:

| Port | Service       | Description                       |
| ---- | ------------- | --------------------------------- |
| 3389 | ms-wbt-server | Remote Desktop Protocol (RDP)     |
| 5985 | wsman         | Windows Remote Management (WinRM) |

These services allow remote management access and may present security risks if misconfigured.

---

## Why Recon Matters

Reconnaissance helps security teams:

* identify exposed services
* understand network structure
* detect potential attack surfaces
* prepare monitoring strategies

---

## MITRE ATT&CK Mapping

Reconnaissance techniques:

* Active scanning
* Network enumeration
* Service discovery





