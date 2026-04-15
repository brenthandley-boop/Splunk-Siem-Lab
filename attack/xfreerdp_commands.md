# xfreerdp RDP Login

## Description

Use xfreerdp to log in to a Windows machine via Remote Desktop Protocol (RDP) using valid credentials.

Protocol: RDP  
Default Port: 3389  
User: Administrator  

---

## Install xfreerdp (Kali Linux)

```bash
sudo apt update
sudo apt install freerdp3-x11 -y
```

---

## Login Command

```bash
xfreerdp /u:Administrator /p:'Password.1**' /v:10.0.*.*
```

---

## Parameters

| Option | Meaning |
|--------|--------|
| /u | username |
| /p | password |
| /v | target IP |
| RDP | remote desktop protocol |

---

## Expected Result

After running the command, a Windows desktop session should appear, confirming successful authentication and RDP access.

---

<img width="1390" height="365" alt="image" src="https://github.com/user-attachments/assets/344e7bf4-4be7-47bb-8675-2395aff2e8d6" />
## Common Issues

* Remote Desktop not enabled on target machine
* Port 3389 blocked by firewall
* Incorrect username or password
* Target IP address incorrect


















