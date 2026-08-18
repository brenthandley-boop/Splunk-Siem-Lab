# CONNECTION-ISSUES.md
## Diagnostic Reference — Every Known Failure Point
### Threat Detection Capstone — The Spelunker-People

---

## Lab environment constraint

> **This VM environment resets automatically every 12 hours.** This is a
> fixed platform behavior of the Fullstack Academy lab infrastructure —
> not configurable, not something to work around by trying to preserve
> state. Every session starts from a fresh install. This is *why* the
> hardening in `LAB-REBUILD-GUIDE.md` is scripted as a single one-time-per-boot
> block (`lab-setup.ps1`) rather than a manual checklist — it needs to
> run identically, correctly, every 12 hours, without relying on memory.

**This document is a reference, not a walkthrough.** For the actual
step-by-step build, use `LAB-REBUILD-GUIDE.md` — it already has every
fix below baked into the default sequence. Come here only when
something breaks mid-run and you need to diagnose why.

> **Build order in one line:** boot Kali → get its IP → do all Windows
> setup + hardening → switch to Kali → install Splunk → verify pipeline →
> run attacks → containment. The full sequence with every command lives in
> `LAB-REBUILD-GUIDE.md`. Do not maintain build steps here — they belong in
> the runbook. This document stays purely diagnostic.

---

## All 13 Connection Failure Categories

---

### Category 1 — VirtualBox Network Adapter Mismatch

**What breaks:** Both VMs need the same network adapter type. If one is NAT and one is Host-Only they cannot see each other at all. This causes 100% connection failure with no obvious error message.

**Prevention:**

VirtualBox → each VM → Settings → Network → Adapter 1. Both must match. Ping to verify:

```bash
ping WINDOWS_IP -c 4
```

Four replies = fine. Timeout = adapter mismatch or VM asleep.

**Recovery:** Match adapter settings in VirtualBox. Power cycle both VMs.

---

### Category 2 — VM Sleep / Display Timeout Mid-Session

**What breaks:** VMs sleep during attacks. Windows falls asleep while Hydra is running, dropping all connections. Most common cause of Hydra dying mid-run.

**Prevention — on Windows:**

```powershell
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
```

**Prevention — on Kali:**

```bash
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
gsettings set org.gnome.desktop.session idle-delay 0
gsettings set org.gnome.desktop.screensaver lock-enabled false
```

**Recovery:** Click into sleeping VM, press any key, wait 30 seconds, run `netstat -an | findstr 3389`, rerun Hydra.

---

### Category 3 — Windows Defender Blocking Hydra

**What breaks:** Defender detects rapid RDP attempts as malicious and blocks the source IP. Looks identical to NLA error but doesn't respond to NLA fix. Hydra dies after ~15 attempts.

**Prevention — on Windows:**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend
```

Confirm:

```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

Must show `True`.

**Recovery:** Unlock account + disable Defender + rerun Hydra:

```powershell
net user labuser01 /active:yes
Set-MpPreference -DisableRealtimeMonitoring $true
```

---

### Category 4 — NLA and Lockout Re-enabling After VM Restart

**What breaks:** NLA disable and lockout settings don't always survive a VM restart. Windows may restore defaults on reboot.

**Prevention:** Run `lab-setup.ps1` at the start of every session. Verify:

```powershell
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication"
```

Must show `UserAuthentication : 0`

```powershell
net accounts | Select-String "Lockout"
```

Must show `Never`

**Recovery:** Rerun the individual fix commands from the lab-setup script.

---

### Category 5 — Hydra.restore File Conflict

**What breaks:** Failed Hydra runs create `hydra.restore`. Rerunning Hydra finds this file and behaves unpredictably — wrong target IP, wrong username, inconsistent behavior.

**Prevention:** Always add `-I` flag to Hydra commands:

```bash
hydra -l labuser01 -P ~/passwords.txt -t 1 -V -I rdp://WINDOWS_IP
```

Or delete before running:

```bash
rm -f ~/hydra.restore
```

---

### Category 6 — RDP Session Limit / Ghost Sessions

**What breaks:** Previous xfreerdp or Hydra sessions that didn't close cleanly leave ghost sessions open. Windows refuses new connections when limit is reached.

**Prevention — on Windows:**

```cmd
query session
```

If any sessions show `Disc` or stuck `Active`:

```cmd
reset session ID_NUMBER
```

Also increase session limit:

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fSingleSessionPerUser" -Value 0
```

---

### Category 7 — Splunk Free Tier 500MB Daily Limit

**What breaks:** Splunk Free indexes maximum 500MB per day. Repeated attacks during testing can hit this limit. Events stop appearing even though attacks are running.

**Check usage:**

```splunk
index=_internal source=*license* earliest=-1d
| stats sum(b) as bytes_used
| eval MB_used=round(bytes_used/1048576,2)
| table MB_used
```

**Prevention:** Run attacks in focused bursts. One Hydra run = ~1-3MB. Don't loop attacks repeatedly during testing.

**Recovery:** Wait until midnight UTC for reset. Run one clean session for screenshots.

---

### Category 8 — Forwarder Not Auto-Starting

**What breaks:** Forwarder service doesn't start automatically on Windows boot. Events never flow to Splunk without manually starting it.

**Prevention:**

```powershell
Set-Service SplunkForwarder -StartupType Automatic
Start-Service SplunkForwarder
```

Confirm:

```powershell
Get-Service SplunkForwarder | Select-Object Name, StartType, Status
```

Both `StartType: Automatic` and `Status: Running` must show.

---

### Category 9 — Windows Update Running During Attacks

**What breaks:** Windows Update triggers automatically during lab sessions, consuming CPU/network. RDP becomes unresponsive and Hydra connections time out.

**Prevention:**

```powershell
Stop-Service wuauserv -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Disabled
```

Or pause through Settings → Windows Update → Advanced Options → Pause.

---

### Category 10 — Time Sync Issues Between VMs

**What breaks:** Different system clocks on Kali and Windows cause Splunk log timestamps to appear out of order. Attack chain timeline visualization shows events in wrong sequence.

**Prevention — set both to UTC:**

**Kali:**

```bash
sudo timedatectl set-ntp true
timedatectl status
```

**Windows:**

```powershell
Set-TimeZone -Id "UTC"
w32tm /resync /force
```

---

### Category 11 — freerdp Certificate Cache After IP Change

**What breaks:** VM resets give it a new IP and new certificate. Kali's cached old certificate causes connection failures.

**Prevention:** Clear cache at start of every session:

```bash
rm -rf ~/.config/freerdp/server/
```

Always use `/cert:ignore` in every xfreerdp command:

```bash
xfreerdp /u:labuser01 /p:'Password.1!!' /v:WINDOWS_IP /cert:ignore
```

---

### Category 12 — Splunk Browser Session Timeout

**What breaks:** Splunk web session times out during long attack runs. You return to find it logged out and miss the live alert firing.

**Prevention — extend session timeout:**

```bash
echo "[settings]
sessionTimeout = 24h" | sudo tee -a /opt/splunk/etc/system/local/web.conf
sudo /opt/splunk/bin/splunk restart
```

Or keep a real-time search running in Splunk to maintain the session while attacks run:

```splunk
index=main EventCode=4625
| stats count by src_ip
| sort - count
```

Set to real-time, 30-second window — session stays alive and shows the attack building.

---

### Category 13 — Kali Terminal Losing Splunk Path

**What breaks:** Running Splunk commands without full path fails after switching terminals.

**Prevention — add to PATH permanently:**

```bash
echo 'export PATH=$PATH:/opt/splunk/bin' >> ~/.bashrc
source ~/.bashrc
```

Now `splunk status` works instead of `sudo /opt/splunk/bin/splunk status`.

---

---

## Quick Reference — Error to Fix

| Exact error or symptom | Category | Fix |
|---|---|---|
| `freerdp: The connection failed to establish` | NLA or Defender | Category 3 + W5a |
| `ERRCONNECT_PASSWORD_MUST_CHANGE` | Forced password change | `net user labuser01 /logonpasswordchg:no` |
| `Host key has changed` / `REMOTE HOST IDENTIFICATION` | Certificate cache | `rm -rf ~/.config/freerdp/server/` |
| `CONNECTION_STATE_NLA` | NLA not disabled | Re-run W5a |
| `all children disabled due to too many errors` | Lockout or Defender | Category 3 + `net accounts /lockoutthreshold:0` |
| `Restorefile (10 seconds to abort)` | hydra.restore conflict | `rm ~/hydra.restore` or add `-I` flag |
| Hydra dies after exactly 4-5 attempts | Account lockout | `net accounts /lockoutthreshold:0` |
| Hydra dies after ~15 attempts | Defender blocking | Category 3 |
| Hydra dies mid-run — was working before | VM went to sleep | Category 2 — wake VM, check `netstat -an \| findstr 3389` |
| No events in Splunk | Forwarder not connected | Check outputs.conf IP, check Forwarder service |
| Events stop appearing mid-session | 500MB limit hit | Category 7 — wait for midnight reset |
| xfreerdp connects then drops | Ghost RDP session | `query session` then `reset session ID` |
| Events appear with wrong timestamps | Clock sync | Category 10 |
| `splunk: command not found` | PATH not set | Category 13 |
| Ping fails between VMs | Network adapter mismatch | Category 1 |
| `Password.3!!` causes wrong command | `!!` bash expansion | Always wrap in single quotes: `'Password.3!!'` |
| Splunk logged out during attack | Session timeout | Category 12 |

---

---

## Complete Workflow Decision Tree

```
START HERE
    │
    ▼
Is this a fresh VM?
    │
    ├── YES
    │     ├── Step 0: Boot Kali → get IP → minimize
    │     ├── Step 1: All Windows work (Forwarder + hardening)
    │     ├── Step 2: Switch to Kali → install Splunk
    │     └── Follow LAB-REBUILD-GUIDE Phase 2 onward
    │
    └── NO (returning session)
          ├── Windows: Run lab-setup.ps1
          ├── Kali: Run pre-session commands
          ├── Verify pipeline (index=main shows events)
          └── Jump to Phase 2 of LAB-REBUILD-GUIDE
```

---

*The Spelunker-People — Fullstack Academy Cybersecurity Bootcamp — April 2026*
