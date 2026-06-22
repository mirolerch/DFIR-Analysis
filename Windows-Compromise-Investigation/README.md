# Windows Endpoint Compromise Investigation

**Case ID:** DFIR-2026-WIN-001  
**Date:** 2026-06-22  
**Analyst:** Miro Lerch  
**Classification:** Confidential — Internal IR Use Only  
**Status:** Remediated

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scenario & Scope](#scenario--scope)
3. [Tools Used](#tools-used)
4. [Investigation Timeline](#investigation-timeline)
5. [Phase 1 - Network Listener Discovery](#phase-1--network-listener-discovery)
6. [Phase 2 - Process Analysis](#phase-2--process-analysis)
7. [Phase 3 - SMB Share Enumeration](#phase-3--smb-share-enumeration)
8. [Phase 4 - Registry Persistence (Run Key)](#phase-4--registry-persistence-run-key)
9. [Phase 5 - Backdoor Service Analysis](#phase-5--backdoor-service-analysis)
10. [Phase 6 - Scheduled Task Analysis](#phase-6--scheduled-task-analysis)
11. [IOC Summary](#ioc-summary)
12. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
13. [Detection Opportunities](#detection-opportunities)
14. [Incident Response Actions](#incident-response-actions)

---

## Executive Summary

A Windows workstation was identified as compromised following the detection of an active network listener and multiple attacker-installed persistence mechanisms. Investigation revealed that the attacker established four distinct persistence methods: a registry Run key, a backdoor Windows service, a scheduled task, and an SMB share pointing to a writable temp directory. All persistence artifacts were mapped, documented, and subsequently removed.

---

## Scenario & Scope

A Windows workstation was flagged for investigation after exhibiting suspicious behavior. The system had been imaged and all forensic artifacts were accessible. The objective was to identify the full scope of compromise - specifically any active network listeners, running malicious processes, and persistence mechanisms installed by the attacker.

**Scope:**
- Host-based investigation on a single Windows workstation
- No lateral movement confirmed at time of investigation
- User account in scope: `psaa`

> **Note:** Certain attacker-planted artifacts (registry Run key, service binary path, scheduled task) reference the hardcoded username `tcm` as embedded by the simulation engine. The actual user account on the investigated system is `psaa`. This discrepancy is reflected in the screenshots and documented here for accuracy.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `netstat` | Network listener and connection enumeration |
| `tasklist` | Process and DLL module enumeration |
| `wmic` | Parent process identification |
| `net share` | SMB share enumeration |
| `reg query` | Registry Run key inspection |
| `sc query` / `sc qc` | Windows service configuration |
| `schtasks` | Scheduled task enumeration |
| Autoruns (Sysinternals) | Autorun entry visualization across all persistence locations |

---

## Investigation Timeline

| Time (UTC) | Action |
|---|---|
| T+00:00 | Investigation initiated; active listener identified on port 50050 |
| T+00:10 | Malicious process (PID 7116) identified and DLL modules enumerated |
| T+00:20 | Attacker-created SMB share `xkalibur` discovered |
| T+00:30 | Registry Run key persistence entry `CleanUpController` identified |
| T+00:45 | Backdoor service `WindowsActiveService` identified with AUTO_START |
| T+01:00 | Scheduled task `ayttpnzc` discovered; execution time confirmed |
| T+01:15 | All IOCs documented; system remediated |

---

## Phase 1 - Network Listener Discovery

**Objective:** Identify any active network listeners that may indicate a C2 channel or backdoor.

**Command:**
```cmd
netstat -anob
```

**Finding:**

The malware was found listening on **TCP port 50050** - a port commonly associated with Cobalt Strike's default Teamserver configuration.

```
Proto  Local Address      Foreign Address   State      PID
TCP    0.0.0.0:50050      0.0.0.0:0         LISTENING  7116
       [challenge.exe]
```

**Screenshot:**

![netstat output](screenshots/netstat%20output.png)

> Port 50050 is the default Cobalt Strike Teamserver port. Its presence on a workstation is a strong indicator of an active C2 listener or beacon staging component.

---

## Phase 2 - Process Analysis

**Objective:** Identify the malicious process by PID and enumerate its loaded DLL modules and parent process.

### 2a - DLL Module Enumeration

**Command:**
```cmd
tasklist /M /FI "PID eq 7116"
```

**Finding:**

Two notable DLLs were loaded that indicate active network socket operations:

| DLL | Purpose |
|---|---|
| `msvcrt.dll` | Microsoft C Runtime Library |
| `mswsock.dll` | Microsoft Windows Sockets - confirms active network operations |

```
Image Name       PID   Modules
challenge.exe    7116  ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                       ADVAPI32.dll, msvcrt.dll, sechost.dll,
                       RPCRT4.dll, WS2_32.dll, ucrtbase.dll, mswsock.dll
```

**Screenshot:**

![tasklist DLL output](screenshots/tasklist%20DLL%20output.png)

### 2b - Parent Process Identification

**Command:**
```cmd
wmic process where "ProcessId=7116" get Name,ParentProcessId
wmic process where "ProcessId=7172" get Name,ProcessId,ParentProcessId
```

**Finding:**

The malicious process `challenge.exe` (PID 7116) had a parent PID of `7172`. Querying that PID confirmed the parent was **`cmd.exe`**, consistent with manual attacker execution from an interactive command prompt session.

```
Name           ParentProcessId
challenge.exe  7172

Name     ParentProcessId  ProcessId
cmd.exe  5352             7172
```

**Screenshot:**

![wmic parent process](screenshots/wmic%20parent%20process.png)

---

## Phase 3 - SMB Share Enumeration

**Objective:** Enumerate all shared resources on the system to identify attacker-created shares.

**Command:**
```cmd
net share
```

**Finding:**

Three default Windows administrative shares were present (`C$`, `IPC$`, `ADMIN$`). One non-standard share was identified:

| Share Name | Resource Path | Notes |
|---|---|---|
| `xkalibur` | `C:\Users\psaa\AppData\Local\Temp\46d5b8556d0d3e30ec1` | Attacker-created - points to Temp directory |

```
Share name   Resource
---------------------------------------------------------------------------
C$           C:\
IPC$
ADMIN$       C:\WINDOWS
xkalibur     C:\Users\psaa\AppData\Local\Temp\46d5b8556d0d3e30ec1
```

**Screenshot:**

![net share output](screenshots/net%20share%20output.png)

> Sharing a user's Temp directory over SMB is a common attacker technique for staging payloads or exfiltrating data. The randomly-named subdirectory (`46d5b8556d0d3e30ec1`) further indicates automated tooling.

---

## Phase 4 - Registry Persistence (Run Key)

**Objective:** Identify attacker-created Run key entries used to maintain persistence across reboots.

**Command:**
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**Finding:**

One legitimate entry (`MicrosoftEdgeAutoLaunch`) and one malicious entry were identified:

| Entry Name | Value | Assessment |
|---|---|---|
| `MicrosoftEdgeAutoLaunch_8D33...` | `msedge.exe --win-session-start` | Legitimate |
| `CleanUpController` | `C:\Users\tcm\Downloads\wininit.exe` | **MALICIOUS** |

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    CleanUpController    REG_SZ    C:\Users\tcm\Downloads\wininit.exe
```

**Full Registry Key Path:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

**Screenshot:**

![reg query Run key](screenshots/reg%20query%20Run%20key.png)

> The entry name `CleanUpController` is crafted to appear as a legitimate maintenance utility. The binary `wininit.exe` in the `Downloads` folder is a significant red flag — the legitimate Windows `wininit.exe` resides in `C:\Windows\System32\`, never in a user's Downloads directory.

---

## Phase 5 - Backdoor Service Analysis

**Objective:** Identify any attacker-installed Windows services configured for persistence.

**Commands:**
```cmd
sc query WindowsActiveService
sc qc WindowsActiveService
```

**Finding:**

A backdoor service named `WindowsActiveService` was found configured for automatic startup under the `LocalSystem` account:

| Property | Value |
|---|---|
| Service Name | `WindowsActiveService` |
| Start Type | `AUTO_START` (2) |
| Binary Path | `C:\Users\tcm\Documents\svcbackdoor.exe` |
| Run As | `LocalSystem` |
| State at Discovery | `STOPPED` |

```
SERVICE_NAME: WindowsActiveService
    TYPE               : 10  WIN32_OWN_PROCESS
    START_TYPE         : 2   AUTO_START
    BINARY_PATH_NAME   : C:\Users\tcm\Documents\svcbackdoor.exe
    SERVICE_START_NAME : LocalSystem
```

**Screenshot:**

![sc qc WindowsActiveService](screenshots/sc%20qc%20WindowsActiveService.png)

> A service binary located in `C:\Users\<user>\Documents\` rather than `C:\Windows\System32\` or `C:\Program Files\` is highly anomalous. `AUTO_START` under `LocalSystem` provides SYSTEM-level persistence that survives reboots without requiring user interaction. The filename `svcbackdoor.exe` leaves no ambiguity as to its purpose.

---

## Phase 6 - Scheduled Task Analysis

**Objective:** Identify attacker-created scheduled tasks used for timed execution of malicious payloads.

**Commands:**
```cmd
schtasks /query /tn "ayttpnzc"
schtasks /query /fo LIST /v /tn "ayttpnzc"
```

**Finding:**

| Property | Value |
|---|---|
| Task Name | `ayttpnzc` |
| Executable | `C:\Users\tcm\Downloads\beac0n.exe` |
| Run As | `psaa` |
| Next Run Time | `2026-06-23 03:30:00 AM` |
| Schedule Type | Daily |
| Status | `Ready` |

```
TaskName                    Next Run Time          Status
ayttpnzc                    6/23/2026 3:30:00 AM   Ready

Task To Run:   C:\Users\tcm\Downloads\beac0n.exe
Run As User:   psaa
Start Time:    3:30:00 AM
Schedule Type: Daily
```

**Screenshot:**

![schtasks output](screenshots/schtasks%20output.png)

> The task name `ayttpnzc` is a random-looking string consistent with automated attacker tooling. The executable `beac0n.exe` (deliberate leet-speak spelling) is a staged beacon payload. Scheduling at 03:30 AM targets a low-activity window to minimize detection probability.

---

## IOC Summary

| Type | Value | Context |
|---|---|---|
| Network Port | `TCP/50050` | Active C2 listener |
| Process | `challenge.exe` (PID 7116) | Malicious listener process |
| SMB Share | `xkalibur` | Attacker-created share |
| Share Path | `C:\Users\psaa\AppData\Local\Temp\46d5b8556d0d3e30ec1` | Staging directory |
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence location |
| Registry Entry | `CleanUpController` | Malicious Run key entry |
| File | `C:\Users\tcm\Downloads\wininit.exe` | Run key payload |
| Service | `WindowsActiveService` | Backdoor service |
| File | `C:\Users\tcm\Documents\svcbackdoor.exe` | Service binary |
| Scheduled Task | `ayttpnzc` | Timed execution task |
| File | `C:\Users\tcm\Downloads\beac0n.exe` | Beacon payload |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence |
|---|---|---|
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | C2 listener on TCP/50050 |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | `netstat -anob`, `tasklist` used to map attacker footprint |
| [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | `net share` revealed attacker-created SMB share `xkalibur` |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Share points to Temp staging directory |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys | `CleanUpController` entry in `HKCU\...\Run` |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Create or Modify System Process: Windows Service | `WindowsActiveService` with AUTO_START |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Task `ayttpnzc` executing `beac0n.exe` at 03:30 AM |

---

## Detection Opportunities

**Network:**
- Alert on any process binding to TCP/50050 — this port has no legitimate use on workstations
- Monitor for outbound connections from user-context processes to non-standard high ports

**Process:**
- Alert on executables running from `C:\Users\*\Downloads\` or `C:\Users\*\Documents\` with network socket activity
- Detect processes loaded with `mswsock.dll` that have no business justification

**Registry:**
- Baseline and alert on new entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Flag binaries in Run keys that reside outside of `C:\Program Files\`, `C:\Windows\`, or `C:\ProgramData\`

**Services:**
- Alert on new services with binaries located in user-writable directories (`%USERPROFILE%`, `%TEMP%`, `%APPDATA%`)
- Flag services configured as `AUTO_START` with `LocalSystem` privileges registered outside system directories

**Scheduled Tasks:**
- Alert on scheduled tasks with randomized or non-descriptive names
- Flag tasks executing binaries from `Downloads` or `Temp` directories
- Monitor task creation events (Windows Event ID 4698)

---

## Incident Response Actions

### Immediate Containment
- [ ] Isolate the host from the network (disable NIC / quarantine in EDR)
- [ ] Terminate the malicious listener process (PID 7116)
- [ ] Remove the SMB share: `net share xkalibur /delete`

### Persistence Removal
- [ ] Delete registry Run key entry: `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v CleanUpController /f`
- [ ] Stop and delete backdoor service: `sc stop WindowsActiveService` → `sc delete WindowsActiveService`
- [ ] Delete scheduled task: `schtasks /delete /tn "ayttpnzc" /f`

### File System Cleanup
- [ ] Remove `C:\Users\tcm\Downloads\wininit.exe`
- [ ] Remove `C:\Users\tcm\Documents\svcbackdoor.exe`
- [ ] Remove `C:\Users\tcm\Downloads\beac0n.exe`
- [ ] Remove staging directory: `C:\Users\psaa\AppData\Local\Temp\46d5b8556d0d3e30ec1\`

### Post-Incident
- [ ] Review authentication logs for the `psaa` account for signs of lateral movement
- [ ] Submit all binaries to VirusTotal and sandbox for behavioral analysis
- [ ] Check other workstations on the same subnet for identical IOCs
- [ ] Patch or harden the initial access vector once identified
- [ ] Update EDR rules and SIEM detections based on IOCs from this investigation
- [ ] Document lessons learned and update IR playbook

---

*Investigation conducted on an isolated forensic workstation. All persistence mechanisms were confirmed removed and the system was verified clean prior to return to service.*
