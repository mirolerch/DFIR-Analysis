````markdown
# Case 01 – Windows Endpoint Compromise Investigation

**Host:** DESKTOP-R39QKFP (Windows 10 Pro x64, build 19041) · **User:** lweber  
**Analyst:** Miroslaw Lerch · **Type:** Lab investigation (simulated adversary activity)  
**All times in UTC.** Local time of the host during the incident: UTC+2.

---

## Executive Summary

On 2026-10-19 an alert reported suspicious PowerShell activity and a new local administrator account on DESKTOP-R39QKFP. Memory and disk were acquired and analysed.

The alert is a **true positive**. Within about 45 seconds (19:09:38 – 19:10:24) a PowerShell script started from the user's Downloads folder:

- downloaded a macro-enabled Office document from the internet,
- created the local administrator account **art-test**,
- ran a Base64 payload stored in the registry,
- installed **five persistence mechanisms** (Run key, two Startup folder scripts, two scheduled tasks, one service),
- injected a DLL into **notepad.exe**.

The service process and the injected notepad.exe were still running when memory was captured (19:22:19). The art-test account was never used to log on. No deletion of evidence was found.

**Impact:** The attacker had administrator rights and several ways to regain access after a reboot. The host must be treated as compromised and rebuilt.

---

## 1. Scenario

### Alert

| Field | Value |
|---|---|
| Alert | Suspicious PowerShell execution – new local admin account created |
| Severity | High |
| Host / User | DESKTOP-R39QKFP / lweber |
| Time | 2026-10-19 ~19:09 UTC |
| Status | Host isolated, memory and disk acquired |

### Scope and Objectives

The investigation answers these questions, using only evidence from the acquired images:

1. Was the alert a true positive?
2. What was executed, when and by whom?
3. Which persistence mechanisms were installed?
4. Was evidence deleted or hidden?
5. What must be done to clean the host and detect this activity in the future?

Out of scope: network traffic analysis, malware reverse engineering, other hosts.

### Intended Audience

- **Management:** Executive Summary and IR Actions
- **SOC / IR team:** Findings, Timeline, IOCs, Detection Opportunities

### Lab Environment

- VirtualBox VM, Windows 10 Pro, local admin user `lweber`
- Sysmon (SwiftOnSecurity config), PowerShell logging, process creation auditing
- Adversary activity simulated with Atomic Red Team

---

## 2. Tools Used

| Phase | Tools |
|---|---|
| Acquisition | VBoxManage (`dumpvmcore`, `clonemedium`), Get-FileHash |
| Preparation | Arsenal Image Mounter (write-temporary mode), KAPE (KapeTriage) |
| Registry | Registry Explorer, RegRipper, AppCompatCacheParser, AmcacheParser |
| File system | MFTECmd ($MFT, $UsnJrnl:$J), Timeline Explorer |
| Execution | PECmd (Prefetch) |
| Persistence | Registry Explorer, Sysinternals Autoruns (offline mode) |
| Event logs | EvtxECmd, Event Log Explorer, CyberChef (Base64 decode) |
| Memory | Volatility 3 (2.28.0), strings |

---

## 3. Findings

### 3.1 Evidence Integrity

| Evidence | SHA256 |
|---|---|
| pf-memory.raw | `BA9347BF3BEBF8F87C77B408887952D53BDB0D376375027AE986F5F5F531511B` |
| pf-disk.vhd | `61F591DCCB88126E45BE1B4B2EE200FAE88AD7CFE5106343FE8C94AF111DC2A2` |

- Memory was captured before disk (order of volatility). Memory capture time per `windows.info`: **19:22:19 UTC**.
- The disk was cloned from the VirtualBox snapshot differencing disk, so it holds the post-attack state.
- Hashes were re-verified after copying to the analysis workstation: identical.
- The image was mounted in write-temporary mode, so the original was not changed.

### 3.2 Timeline of the Attack

| UTC | Event | Evidence |
|---|---|---|
| 19:01:16 | Defender real-time protection disabled | Defender 5001, SOFTWARE (LastWrite 19:01:15) |
| 19:07:46 | System reboot | SYSTEM ShutdownTime |
| 19:08:07 | lweber logs on | SAM, Security 4624 |
| 19:08:14 | Windows Security app opened | UserAssist |
| 19:08:22 | Defender real-time protection disabled again | Defender 5001 |
| 19:08:52 | PowerShell launched by the user | UserAssist, JumpList |
| **19:09:38** | `Set-ExecutionPolicy Bypass`, then `.\ART-attack.ps1` from `Downloads\PWF-main\AtomicRedTeam` | PSReadLine history (last write) |
| 19:09:42 | `C:\AtomicRedTeam` created; csc.exe compiles C# code | ShellBags, Prefetch, USN |
| 19:10:03 | Framework archives extracted and deleted | USN Journal |
| **19:10:04** | Download of `PhishingAttachment.xlsm` to `%TEMP%` | PowerShell 400 |
| **19:10:07** | net.exe / net1.exe: account **art-test** created and added to Administrators; whoami, hostname | SAM, Prefetch, USN |
| **19:10:10–13** | Base64 payload written to `HKCU\Software\Classes\AtomicRedTeam` and executed; Run key **"Atomic Red Team"** set | PowerShell 400, NTUSER.DAT, Prefetch (reg.exe) |
| **19:10:16** | `batstartup.bat` copied to both Startup folders and executed | PowerShell 400, Prefetch (cmd.exe ×2) |
| **19:10:18** | Scheduled tasks `T1053_005_OnLogon` / `T1053_005_OnStartup` created | TaskCache, Task XML, Prefetch |
| **19:10:20** | Service **AtomicTestService_CMD** installed and started (PID 6844) | System 7045, SYSTEM, Prefetch, Volatility |
| **19:10:24** | notepad.exe (PID 3516) started, mavinject injects DLL | PowerShell 400, Prefetch, Volatility |
| 19:22:19 | Memory captured | Volatility `windows.info` |

### 3.3 Initial Execution

- The PSReadLine history of lweber shows that the user ran `Set-ExecutionPolicy Bypass -Scope Process -Force` and then `.\ART-attack.ps1`. The last write of the history file was 19:09:38.
- ART-attack.ps1 (MFT entry 106065) is **not timestomped**: $SI Created = $FN Created. The old $SI Modified date (2026-02-16) was inherited when the file was copied.
- PowerShell Engine events (Event 400) show the commands that each child PowerShell ran in the `HostApplication` field.

### 3.4 Account Creation

| Item | Value |
|---|---|
| Account | **art-test**, RID 1002 |
| Created | 19:10:07 |
| Group | Administrators (group LastWrite 19:10:07) |
| Logons | **None.** Login count 0, no profile, no 4624 event |
| Tool | net.exe / net1.exe, first execution 19:10:07 (Prefetch) |

### 3.5 Execution of Additional Payloads

**Download (19:10:04)**

```powershell
$url = 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm'
Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm
```

**Payload stored in the registry (19:10:10)**

```
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQg..."
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
```

Decoded with CyberChef:

```powershell
Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team"
```

Both files exist on disk: `C:\Windows\Temp\art-marker.txt` and `PhishingAttachment.xlsm` (13,517 bytes) in the Temp folder of lweber. There is no evidence that the document was opened (no Office process in Prefetch).

**Process injection (19:10:23)**

```powershell
$mypid = (Start-Process notepad -PassThru).id
mavinject $mypid /INJECTRUNNING C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll
```

### 3.6 Persistence Mechanisms

| # | Mechanism | Detail | Created | Status |
|---|---|---|---|---|
| 1 | HKCU Run key | `Atomic Red Team` → `C:\Path\AtomicRedTeam.exe` | 19:10:13 | Target file does not exist (Autoruns: "File not found") |
| 2 | Startup folder (all users) | `C:\ProgramData\...\StartUp\batstartup.bat` (34 bytes) | 19:10:16 | Present, runs at every logon |
| 3 | Startup folder (lweber) | `%APPDATA%\...\Startup\batstartup.bat` | 19:10:16 | Present, runs at every logon of lweber |
| 4 | Scheduled task | `\T1053_005_OnLogon`, LogonTrigger, `cmd.exe /c calc.exe`, author lweber | 19:10:18 | Enabled, never run |
| 5 | Scheduled task | `\T1053_005_OnStartup`, BootTrigger, `cmd.exe /c calc.exe`, author lweber | 19:10:18 | Enabled, never run |
| 6 | Service | `AtomicTestService_CMD`, `C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe`, demand start, LocalSystem, unsigned | 19:10:20 | Running (PID 6844), but does not start by itself after reboot |

The content of batstartup.bat is `echo " T1547.001 Hello World Bat"`. The payload is harmless, but the mechanism is real persistence.

### 3.7 Program Execution

| Program | Run time (UTC) | Evidence |
|---|---|---|
| csc.exe | 19:09:42 | Prefetch (first run), USN (temp .cs/.dll deleted) |
| net.exe ×3, net1.exe, whoami.exe, hostname.exe | 19:10:07 | Prefetch (first run) |
| reg.exe ×2 | 19:10:11, 19:10:13 | Prefetch |
| cmd.exe ×2 | 19:10:16 | Prefetch |
| schtasks.exe ×2 | 19:10:18 | Prefetch (first run) |
| sc.exe ×2, AtomicService.exe (run count 1) | 19:10:20 | Prefetch |
| mavinject.exe, notepad.exe | 19:10:24 | Prefetch, BAM (notepad 19:10:24) |

- **BAM:** shows cmd.exe 19:10:20, notepad.exe and powershell.exe 19:10:24, but only after the transaction logs were replayed.
- **ShimCache:** contains no attack entries. It is only written at shutdown, and the last shutdown (19:07:46) was before the attack.
- **Amcache:** was not updated for the attack window. The newest entry is msedge.exe at 19:09:07.

### 3.8 Memory Analysis

| PID | Process | PPID | Created | State at capture |
|---|---|---|---|---|
| 4656 | powershell.exe | 4344 | 19:10:22 | Exited 19:10:24 |
| **3516** | **notepad.exe** | 4656 | 19:10:24 | **Running** (injection target) |
| 540 | mavinject.exe | 4656 | 19:10:24 | – |
| **6844** | **AtomicService.exe** | 632 | 19:10:20 | **Running**, session 0 (service) |

- AtomicService.exe was dumped from memory. It has a valid PE header and the manifest `MyApplication.app`.
- `malfind`, `dlllist` and `vadinfo` returned no data for PID 3516. The injection is therefore proven by PowerShell Event 400, Prefetch and the process tree, not by memory artifacts.

### 3.9 Anti-Forensics

- **No evidence deleted.** The USN Journal shows no deletion of scripts, tools, logs or output in the attack window. The deletions found are installer and temp cleanup (framework archives, `__PSScriptPolicyTest_*` files, Edge, WMI).
- **No timestomping** found on the investigated files.

### 3.10 Indicators of Compromise

| Type | Indicator |
|---|---|
| Account | `art-test` (RID 1002, member of Administrators) |
| File | `C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe` – SHA1 `C51217CE3D1959E99886A567D21D0B97022BD6E3` |
| File | `C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll` |
| File | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat` |
| File | `C:\Users\lweber\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat` |
| File | `C:\Users\lweber\AppData\Local\Temp\PhishingAttachment.xlsm` (13,517 bytes, written 19:10) |
| File | `C:\Windows\Temp\art-marker.txt` |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `Atomic Red Team` |
| Registry | `HKCU\Software\Classes\AtomicRedTeam` (value `ART`, Base64) |
| Service | `AtomicTestService_CMD` |
| Tasks | `\T1053_005_OnLogon`, `\T1053_005_OnStartup` |
| URL | `https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm` |

### 3.11 Alternative Explanations

| Observation | Alternative explanation | Assessment |
|---|---|---|
| Malicious activity on the host | Authorized red team test | Cannot be decided from the image. Without confirmation (ticket, test announcement) it is handled as a real attack. |
| Defender disabled before the attack | Administrator change, not the attacker | Plausible. Windows Security was opened at 19:08:14 and protection was turned off at 19:08:22 by the logged-on user through the GUI, not by the script. Still a security gap. |
| Old $SI Modified date on ART-attack.ps1 and batstartup.bat | Timestomping | Rejected. $SI Created = $FN Created; the old date was inherited from the source files on copy. |
| Timestamps on 2026-10-20 03:30 UTC (setup keys, events from WIN-HQSNIUMIHAR) | Activity after the incident | Rejected. These come from the Windows setup phase (clock offset +9 h, original computer name). They are not related to the attack. |
| Two 4624 events with different Logon IDs at the same second | Two separate logons | Rejected. This is the UAC split token of an admin account. 4672 is assigned to Logon ID 0x1f1fcb, the elevated session. |
| No attack entries in ShimCache / Amcache | No execution | Rejected. ShimCache is written only at shutdown and Amcache was not yet updated. Prefetch, BAM, event logs and memory confirm the execution. |

### 3.12 Limitations

- **AtomicService.exe path conflict.** Prefetch references the executable under `\AtomicRedTeam\tmp\atomic-red-team-724cb3f5…\atomics\...`, while the service and Autoruns point to `C:\AtomicRedTeam\atomics\...`. Not resolved.
- **AtomicService.exe** is not in Amcache. The SHA1 was calculated from the file on the mounted image.
- **Sysmon process creation events** (Event 1) were not analysed per command line.
- **KAPE triage** did not collect the Startup folders. They were checked on the mounted image.
- **No super timeline** (Plaso) was built. The timeline is based on Prefetch, Registry, Event Logs, USN Journal and memory.

---

## 4. Commands

**Acquisition**

```
VBoxManage debugvm <VM-UUID> dumpvmcore --filename C:\Evidence\pf-memory.raw
VBoxManage clonemedium disk <differencing-disk-UUID> --format VHD C:\Evidence\pf-disk.vhd
Get-FileHash -Algorithm SHA256 C:\Evidence\*
```

**Triage**

```
kape.exe --tsource F: --tdest C:\Cases\KAPE\Targets --target KapeTriage
```

**Registry**

```
for %i in (*) do (rip.exe -r "%i" -a > "C:\Cases\Analysis\RegRipper\%~nxi.txt")
AppCompatCacheParser.exe -f C:\Cases\Analysis\Registry\SYSTEM --csv C:\Cases\Analysis\Exec
AmcacheParser.exe -f C:\Cases\KAPE\Targets\F\Windows\AppCompat\Programs\Amcache.hve --csv C:\Cases\Analysis\Execution
```

**NTFS**

```
MFTECmd.exe -f C:\Cases\KAPE\Targets\F\$MFT --csv C:\Cases\Analysis\NTFS --csvf MFT.csv
MFTECmd.exe -f C:\Cases\KAPE\Targets\F\$MFT --de 106065
MFTECmd.exe -f "C:\Cases\KAPE\Targets\F\$Extend\$J" -m "C:\Cases\KAPE\Targets\F\$MFT" --csv "C:\Cases\Analysis\USN Journal" --csvf USNJRNL.csv
```

**Prefetch**

```
PECmd.exe -f C:\Cases\KAPE\Targets\F\Windows\prefetch\ATOMICSERVICE.EXE-94EEF3DF.pf
PECmd.exe -d "C:\Cases\KAPE\Targets\F\Windows\prefetch" --csv "C:\Cases\Analysis\Execution" --csvf Prefetch.csv
```

**Persistence and file checks**

```powershell
Get-FileHash -Algorithm SHA1 "F:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe"
Test-Path "F:\Users\lweber\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Test-Path "F:\Windows\Temp\art-marker.txt"
Get-ChildItem -Force F:\Windows\System32\Tasks\T1053*
Select-String -Path F:\Windows\System32\Tasks\T1053* -Pattern "Trigger" -Context 0,3
```

**Event logs**

```
EvtxECmd.exe -d C:\Cases\KAPE\Targets\F\Windows\System32\winevt\logs --csv C:\Cases\Analysis\EventLogs
```

**Memory**

```
vol -f pf-memory.raw windows.info
vol -f pf-memory.raw windows.pstree > pstree.txt
vol -f pf-memory.raw windows.pslist --pid 3516 6844
vol -f pf-memory.raw -o . windows.pslist --pid 6844 --dump
strings 6844.AtomicService..0x720000.dmp
vol -f pf-memory.raw windows.malfind --pid 3516
vol -f pf-memory.raw windows.dlllist --pid 3516
```

---

## 5. Screenshots

All screenshots are stored in the folder `screenshots/`. The figure number is the start of the file name.

### Acquisition and preparation

**Figure 1 – Memory acquisition with VBoxManage dumpvmcore** (see 3.1)

![Figure 1](screenshots/01_memory_acquisition.png)

**Figure 2 – Disk clone from the snapshot differencing disk** (see 3.1)

![Figure 2](screenshots/02_disk_clone.png)

**Figure 3 – SHA256 hashes of memory and disk image** (see 3.1)

![Figure 3](screenshots/03_evidence_hashes.png)

**Figure 4 – Image mounted with Arsenal Image Mounter (write-temporary)** (see 3.1)

![Figure 4](screenshots/04_image_mounted.png)

**Figure 5 – KAPE triage output** (see 3.1)

![Figure 5](screenshots/05_kape_triage.png)

### Registry and user behavior

**Figure 6 – SAM – account art-test (RID 1002), created 19:10:07** (see 3.4)

![Figure 6](screenshots/06_sam_art-test_account.png)

**Figure 7 – SAM – Administrators group incl. art-test** (see 3.4)

![Figure 7](screenshots/07_sam_administrators_group.png)

**Figure 8 – Defender real-time protection disabled** (see 3.2)

![Figure 8](screenshots/08_defender_settings.png)

**Figure 9 – ShellBags Explorer – C:\AtomicRedTeam (logs replayed)** (see 3.2)

![Figure 9](screenshots/09_shellbags_atomicredteam.png)

**Figure 10 – BAM – RegRipper (no logs) vs. Registry Explorer (logs replayed)** (see 3.7)

![Figure 10](screenshots/10_bam_comparison.png)

### NTFS and execution

**Figure 11 – MFT record of ART-attack.ps1 ($SI / $FN)** (see 3.3)

![Figure 11](screenshots/11_mft_art-attack_ps1.png)

**Figure 12 – PSReadLine ConsoleHost_history.txt** (see 3.3)

![Figure 12](screenshots/12_powershell_history.png)

**Figure 13 – USN Journal – new .pf files in the attack window** (see 3.7)

![Figure 13](screenshots/13_usn_new_prefetch_files.png)

**Figure 14 – PECmd – ATOMICSERVICE.EXE (run count, last run, path)** (see 3.7)

![Figure 14](screenshots/14_pecmd_atomicservice.png)

**Figure 15 – Prefetch timeline 19:09–19:25** (see 3.7)

![Figure 15](screenshots/15_prefetch_timeline.png)

### Persistence

**Figure 16 – HKCU Run key "Atomic Red Team"** (see 3.6)

![Figure 16](screenshots/16_hkcu_run_key.png)

**Figure 17 – batstartup.bat in the StartUp folder** (see 3.6)

![Figure 17](screenshots/17_startup_batstartup.png)

**Figure 18 – Service AtomicTestService_CMD** (see 3.6)

![Figure 18](screenshots/18_service_atomictestservice.png)

**Figure 19 – TaskCache – T1053_005 tasks** (see 3.6)

![Figure 19](screenshots/19_scheduled_tasks_taskcache.png)

**Figure 20 – Task XML triggers (LogonTrigger / BootTrigger)** (see 3.6)

![Figure 20](screenshots/20_scheduled_tasks_triggers.png)

**Figure 21 – Autoruns – Logon and Services** (see 3.6)

![Figure 21](screenshots/21_autoruns.png)

### Event logs

**Figure 22 – Defender events 5000 / 5001** (see 3.2)

![Figure 22](screenshots/22_defender_5000_5001.png)

**Figure 23 – System 7045 – service installed** (see 3.6)

![Figure 23](screenshots/23_system_7045.png)

**Figure 24 – Security 4624 / 4672 – logon IDs** (see 3.11)

![Figure 24](screenshots/24_security_4624_4672.png)

**Figure 25 – PowerShell 400 – PhishingAttachment.xlsm download** (see 3.5)

![Figure 25](screenshots/25_powershell_400_download.png)

**Figure 26 – PowerShell 400 – Base64 payload in the registry** (see 3.5)

![Figure 26](screenshots/26_powershell_400_registry_payload.png)

**Figure 27 – CyberChef – decoded payload** (see 3.5)

![Figure 27](screenshots/27_cyberchef_base64.png)

**Figure 28 – PowerShell 400 – batstartup.bat copied to Startup folders** (see 3.6)

![Figure 28](screenshots/28_powershell_400_startup.png)

**Figure 29 – PowerShell 400 – mavinject injection into notepad** (see 3.5)

![Figure 29](screenshots/29_powershell_400_mavinject.png)

### Memory and file checks

**Figure 30 – Volatility windows.info – capture time 19:22:19** (see 3.8)

![Figure 30](screenshots/30_vol_windows_info.png)

**Figure 31 – Volatility windows.pstree – attack processes** (see 3.8)

![Figure 31](screenshots/31_vol_pstree.png)

**Figure 32 – AtomicService.exe dump and strings** (see 3.8)

![Figure 32](screenshots/32_vol_atomicservice_dump.png)

**Figure 33 – SHA1 of AtomicService.exe and file checks** (see 3.10)

![Figure 33](screenshots/33_file_checks_sha1.png)

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | PowerShell | T1059.001 | PSReadLine history, PowerShell 400 |
| Execution | Windows Command Shell | T1059.003 | cmd.exe Prefetch, task actions |
| Defense Evasion | Obfuscated Files or Information (Base64) | T1027 | Payload in registry value ART |
| Defense Evasion | Modify Registry | T1112 | `HKCU\Software\Classes\AtomicRedTeam` |
| Defense Evasion | Process Injection: DLL Injection | T1055.001 | mavinject → notepad.exe |
| Defense Evasion | System Binary Proxy Execution (mavinject) | T1218 | mavinject.exe `/INJECTRUNNING` |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Defender 5001 (see Alternative Explanations) |
| Persistence | Create Account: Local Account | T1136.001 | art-test, SAM, net1.exe |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | HKCU Run, batstartup.bat |
| Persistence | Scheduled Task | T1053.005 | T1053_005_OnLogon / OnStartup |
| Persistence | Windows Service | T1543.003 | AtomicTestService_CMD, 7045 |
| Discovery | System Owner/User Discovery | T1033 | whoami.exe |
| Discovery | System Information Discovery | T1082 | hostname.exe |
| Command and Control | Ingress Tool Transfer | T1105 | Invoke-WebRequest download |
| Initial Access (simulated) | Spearphishing Attachment | T1566.001 | PhishingAttachment.xlsm downloaded, not opened |

T1078.003 (Valid Accounts: Local Accounts) does **not** apply. The art-test account was never used to log on.

---

## 7. Detection Opportunities

| # | Detection | Data source |
|---|---|---|
| 1 | `net.exe` / `net1.exe` with `user /add` or `localgroup administrators /add` | Sysmon 1 / Security 4688 |
| 2 | New local account and admin group change | Security 4720, 4732 |
| 3 | Service installed with an image path outside `C:\Windows` or `C:\Program Files` | System 7045 |
| 4 | Scheduled task created by a user with cmd.exe / powershell.exe as action | Security 4698, TaskScheduler 106 |
| 5 | New value in Run / RunOnce keys | Sysmon 13 |
| 6 | File created in any Startup folder | Sysmon 11 |
| 7 | `mavinject.exe` with `/INJECTRUNNING` (rarely used legitimately) | Sysmon 1 / 4688 |
| 8 | PowerShell with `FromBase64String` + `iex`, or `Invoke-WebRequest` to download Office macro files | PowerShell 4104 / 400 |
| 9 | `Set-ExecutionPolicy Bypass` followed by a script from the Downloads folder | PowerShell 4104 |
| 10 | Defender real-time protection disabled | Defender 5001 |
| 11 | Correlation: several of the above on one host within 60 seconds | SIEM rule |

---

## 8. IR Actions

**Containment**

- Keep the host isolated from the network (done).
- Disable the account `art-test`.
- Reset the password of `lweber`. The account ran the script and is a local admin.

**Eradication** (if the host is cleaned instead of rebuilt)

- Stop and delete the service `AtomicTestService_CMD`.
- Delete the scheduled tasks `\T1053_005_OnLogon` and `\T1053_005_OnStartup`.
- Remove the Run value `Atomic Red Team` and the key `HKCU\Software\Classes\AtomicRedTeam`.
- Delete `batstartup.bat` from both Startup folders.
- Delete `C:\AtomicRedTeam`, `%TEMP%\PhishingAttachment.xlsm`, `C:\Windows\Temp\art-marker.txt` and `Downloads\PWF-main`.
- Delete the account `art-test`.
- Terminate notepad.exe (PID 3516), or reboot after the cleanup.

**Recovery**

- Preferred: rebuild the host from a known-good image. In the lab, restore the snapshot taken before the attack.
- Re-enable Defender real-time protection and turn on Tamper Protection.
- Monitor the host for repeated activity using the IOCs in 3.10.

**Lessons Learned**

- Users must not be local administrators.
- Restrict PowerShell for standard users (AppLocker/WDAC, Constrained Language Mode). Do not allow `Set-ExecutionPolicy Bypass`.
- Block or alert on `mavinject.exe`.
- Forward Sysmon, Security, System and PowerShell logs to the SIEM and add the detections in section 7.
- Always analyse registry hives together with their transaction logs. In this case the service, the scheduled tasks, the BAM entries and the ShellBags were only visible after the logs were replayed.
````
